"use strict";
// Tiny cron -> plain English for the common shapes. Returns null when unsure;
// callers always keep the raw expression next to it.
const DOW = [
  "Sunday",
  "Monday",
  "Tuesday",
  "Wednesday",
  "Thursday",
  "Friday",
  "Saturday",
];
const num = (s) => /^\d{1,2}$/.test(s);
const list = (s) =>
  /^\d{1,2}(,\d{1,2}){0,23}$/.test(s) ? s.split(",").map(Number) : null;
const p2 = (n) => String(n).padStart(2, "0");

function describeCron(expr) {
  if (typeof expr !== "string") return null;
  let f = expr.trim().split(/\s+/);
  if (f.length === 6) f = f.slice(1);
  if (f.length !== 5) return null;
  const [m, h, dom, mon, dow] = f;
  let time = null;
  const mins = list(m);
  const hrs = list(h);
  let step;
  if (mins && hrs && mins.length * hrs.length <= 6) {
    const t = [];
    for (const hh of hrs) for (const mm of mins) t.push(`${p2(hh)}:${p2(mm)}`);
    time = `at ${t.join(", ")}`;
  } else if (m === "*" && h === "*") time = "every minute";
  else if ((step = /^\*\/(\d{1,2})$/.exec(m)) && h === "*")
    time = `every ${step[1]} minutes`;
  else if (mins && (step = /^\*\/(\d{1,2})$/.exec(h)))
    time = `every ${step[1]} hours at minute ${mins.join(", ")}`;
  else if (mins && h === "*") time = `every hour at minute ${mins.join(", ")}`;
  else if (mins && hrs)
    time = `at minute ${mins.join(", ")} of hours ${hrs.join(", ")}`;
  if (!time) return null;
  let day = "";
  if (mon !== "*")
    return `${time} (restricted months, read the cron expression)`;
  if (dom === "*" && dow === "*") day = "every day";
  else if (dom === "*" && dow === "1-5") day = "on weekdays";
  else if (dom === "*" && list(dow))
    day = `on ${list(dow)
      .map((d) => DOW[d % 7])
      .join(", ")}`;
  else if (dow === "*" && list(dom))
    day = `on day ${list(dom).join(", ")} of the month`;
  else if (dow === "*" && dom === "*") day = "every day";
  else return `${time} (day rules, read the cron expression)`;
  return `${time}, ${day}`;
}

module.exports = { describeCron };
