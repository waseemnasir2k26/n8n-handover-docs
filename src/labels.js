"use strict";
// Data only: words that label a credential, per language. Shared by the name policy
// (src/policy.js) and the final gate (src/gate.js); the README language list is generated from
// LANGUAGES (npm run readme:langs). Multi-word labels are listed joined; the matcher joins up to
// three adjacent tokens. strong = a password-type word (a value follows), weak = only a
// value-looking token after it counts, cjk = matched as a substring (scripts without spaces).
const { fold } = require("./value-rule");
// Label sets are folded with the same fold() as the tokens they are matched against (diacritics, marks,
// look-alike letters). CJK labels stay NFKC-only: they are matched as raw substrings.
const norm = (s) => s.normalize("NFKC").toLowerCase();

const BY_LANG = {
  English: {
    strong: [
      "password",
      "passwd",
      "passphrase",
      "passcode",
      "pass",
      "pwd",
      "pw",
      "secret",
      "secrets",
      "clientsecret",
    ],
    weak: [
      "token",
      "tokens",
      "key",
      "keys",
      "apikey",
      "privatekey",
      "bearer",
      "otp",
      "auth",
      "authtoken",
      "accesstoken",
      "refreshtoken",
      "authorization",
      "login",
      "access",
      "credentials",
      "credential",
      "creds",
      "cred",
      "apitoken",
    ],
  },
  Spanish: {
    strong: ["contraseña", "contrasena", "clave", "secreto"],
    weak: ["llave"],
  },
  Portuguese: { strong: ["senha", "segredo", "palavrapasse"], weak: ["chave"] },
  French: {
    strong: ["motdepasse", "mdp", "secretcode"],
    weak: ["jeton", "clé", "cle"],
  },
  German: {
    strong: ["passwort", "kennwort", "geheimnis", "losungswort", "zugangscode"],
    weak: ["schlüssel", "schluessel", "zugangsdaten"],
  },
  Turkish: { strong: ["şifre", "sifre", "parola"], weak: ["anahtar"] },
  Indonesian: { strong: ["katasandi", "sandi", "rahasia"], weak: ["kunci"] },
  Vietnamese: {
    strong: ["mậtkhẩu", "matkhau", "mậtkhâu"],
    weak: [],
  },
  Russian: {
    strong: ["пароль", "парол", "пин", "секрет", "паролю"],
    weak: ["ключ", "токен", "логин"],
  },
  Arabic: {
    strong: ["كلمةالسر", "كلمةالمرور", "كلمهالسر", "كلمهالمرور", "السر", "سر"],
    weak: ["مفتاح", "رمز"],
  },
  Hindi: { strong: ["पासवर्ड", "पासकोड", "गुप्त"], weak: ["कुंजी"] },
  Urdu: { strong: ["پاسورڈ", "خفیہ"], weak: [] },
  Thai: { strong: ["รหัสผ่าน"], weak: ["รหัส"], cjk: ["รหัสผ่าน"] },
  Japanese: {
    strong: ["パスワード", "パス", "暗証番号", "合言葉", "あいことば"],
    weak: ["トークン", "キー"],
    cjk: ["パスワード", "暗証番号", "合言葉"],
  },
  Korean: {
    strong: ["비밀번호", "암호", "패스워드", "비번"],
    weak: ["토큰", "키"],
    cjk: ["비밀번호", "패스워드", "암호"],
  },
  Chinese: {
    strong: ["密码", "密碼", "口令", "密令"],
    weak: ["令牌", "密钥", "秘钥", "密鑰"],
    cjk: ["密码", "密碼", "口令", "密钥", "密鑰", "秘钥", "令牌"],
  },
};

// emoji that label a value (variation selectors are stripped before matching)
const EMOJI_LABELS = ["🔑", "🔐", "🗝", "🔒"];

// Code-type labels: a numeric / spoken / NATO value after them is redacted
const PIN_LABELS = [
  "pin",
  "otp",
  "passcode",
  "pincode",
  "pinnumber",
  "accesscode",
  "doorcode",
  "gatecode",
  "safecode",
  "alarmcode",
  "securitycode",
  "verificationcode",
  "verifycode",
  "unlockcode",
  "entrycode",
  "cvv",
  "cvv2",
  "cvc",
  "cvc2",
  "sortcode",
  "accountnumber",
  "accountno",
  "zugangscode",
];
const SPOKEN_DIGITS = [
  "zero",
  "oh",
  "one",
  "two",
  "three",
  "four",
  "five",
  "six",
  "seven",
  "eight",
  "nine",
  "niner",
];
const NATO = [
  "alpha",
  "alfa",
  "bravo",
  "charlie",
  "delta",
  "echo",
  "foxtrot",
  "golf",
  "hotel",
  "india",
  "juliet",
  "juliett",
  "kilo",
  "lima",
  "mike",
  "november",
  "oscar",
  "papa",
  "quebec",
  "romeo",
  "sierra",
  "tango",
  "uniform",
  "victor",
  "whiskey",
  "xray",
  "yankee",
  "zulu",
];

// A spaced run of digits after one of these is a code (safe, door, alarm, pin)
const CODE_WORDS = [
  "code",
  "pin",
  "safe",
  "door",
  "alarm",
  "combination",
  "lock",
  "vault",
  "keypad",
  "passcode",
  "codigo",
  "código",
  "kod",
  "cifra",
  "код",
  "الرمز",
];

const all = (k) => Object.values(BY_LANG).flatMap((l) => l[k] || []);

// A label glued to a prefix with no separator (DBpwd, rootpassword, mytoken, DBPIN). Long, unambiguous words only.
const SUFFIX_LABELS = [
  "password",
  "passwd",
  "passwort",
  "kennwort",
  "passphrase",
  "passcode",
  "secret",
  "secreto",
  "segredo",
  "token",
  "pwd",
  "cvv",
  "cvc",
  "zugangscode",
  "contrasena",
  "motdepasse",
  "apikey",
  "authtoken",
  "credentials",
  "credential",
];

// Label variants: "password1", "pass2", "pin2", "apikey2" match their label (trailing digits or
// underscores dropped), and "passwords" matches "password" (plural s dropped). The bare word is tried first.
function labelVariants(w) {
  const l = fold(w);
  const base = l.replace(/[\p{N}_]+$/u, "");
  return [l, base, base.replace(/s$/, "")];
}
const inLabelSet = (set, w) => labelVariants(w).some((v) => set.has(v));

module.exports = {
  inLabelSet,
  labelVariants,
  SUFFIX_LABELS,
  BY_LANG,
  LANGUAGES: Object.keys(BY_LANG),
  STRONG: new Set(all("strong").map(fold)),
  WEAK: new Set(all("weak").map(fold)),
  CJK_LABELS: all("cjk").map(norm),
  CODE_WORDS: new Set(CODE_WORDS.map(fold)),
  ALL_LABELS: [...all("strong"), ...all("weak")].map(fold),
  EMOJI_LABELS,
  PIN_LABELS: new Set(PIN_LABELS.map(fold)),
  SPOKEN_DIGITS: new Set(SPOKEN_DIGITS),
  NATO: new Set(NATO),
};
