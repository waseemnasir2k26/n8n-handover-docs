"use strict";
// Data only: words that label a credential, in several languages. Shared by the name policy
// (src/policy.js) and the final gate (src/gate.js). Whole-token words; multi-word labels are
// listed joined (the matcher joins up to three adjacent tokens).
const norm = (s) => s.normalize("NFKC").toLowerCase();

// A value usually follows these: password-type words
const STRONG_LIST = [
  // en
  "password",
  "passwd",
  "passphrase",
  "passcode",
  "pass",
  "pwd",
  "pw",
  "secret",
  "secrets",
  "apikey",
  "clientsecret",
  "privatekey",
  "sk",
  // es / pt
  "contraseña",
  "contrasena",
  "clave",
  "secreto",
  "senha",
  "segredo",
  "palavrapasse",
  // fr
  "motdepasse",
  "mdp",
  "secretcode",
  // de
  "passwort",
  "kennwort",
  "geheimnis",
  "losungswort",
  // tr / id
  "şifre",
  "sifre",
  "parola",
  "katasandi",
  "sandi",
  "rahasia",
  // ru / uk
  "пароль",
  "парол",
  "пин",
  "секрет",
  "паролю",
  // ar
  "كلمةالسر",
  "كلمةالمرور",
  "كلمهالسر",
  "كلمهالمرور",
  "السر",
  "سر",
  // hi / ur
  "पासवर्ड",
  "पासकोड",
  "गुप्त",
  "پاسورڈ",
  "خفیہ",
  // ja
  "パスワード",
  "パス",
  "暗証番号",
  "合言葉",
  "あいことば",
  // ko
  "비밀번호",
  "암호",
  "패스워드",
  "비번",
  // zh (also matched as substrings of CJK tokens)
  "密码",
  "密碼",
  "口令",
  "密令",
];

// Weak: a value only counts when it is value-like or follows an explicit marker
const WEAK_LIST = [
  "token",
  "tokens",
  "key",
  "keys",
  "bearer",
  "otp",
  "auth",
  "authtoken",
  "accesstoken",
  "refreshtoken",
  "authorization",
  "login",
  "credentials",
  "credential",
  "creds",
  "cred",
  "apitoken",
  "llave",
  "chave",
  "jeton",
  "clé",
  "cle",
  "schlüssel",
  "schluessel",
  "anahtar",
  "kunci",
  "ключ",
  "токен",
  "логин",
  "مفتاح",
  "رمز",
  "कुंजी",
  "令牌",
  "密钥",
  "秘钥",
  "密鑰",
  "トークン",
  "キー",
  "토큰",
  "키",
];

// Substrings in scripts without spaces (matched inside a token)
const CJK_LABELS = [
  "密码",
  "密碼",
  "口令",
  "密钥",
  "密鑰",
  "秘钥",
  "令牌",
  "パスワード",
  "暗証番号",
  "合言葉",
  "비밀번호",
  "패스워드",
  "암호",
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
  "codé",
  "код",
  "الرمز",
];

module.exports = {
  STRONG: new Set(STRONG_LIST.map(norm)),
  WEAK: new Set(WEAK_LIST.map(norm)),
  CJK_LABELS: CJK_LABELS.map(norm),
  CODE_WORDS: new Set(CODE_WORDS.map(norm)),
  ALL_LABELS: [...STRONG_LIST, ...WEAK_LIST].map(norm),
};
