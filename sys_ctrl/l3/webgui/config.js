/*
 * sys_ctrl/l3/webgui/config.js
 *
 * New in the modern tree: gui/config.cc for the web l2gui. The command
 * destination ("r 1,3 s *", "p 2", ...) and its rack/slot/partition
 * selection lists (CmdData rlist[256]/slist[64]/plist[64]), parsed as the
 * L2's command parser (common/sys/Cmd.c: match_dest, match_range) does.
 */

import { mainwin_update_dest } from "./mainwin.js";

export const CMD_RANGE_NONE = 0, CMD_RANGE_ONE = 1, CMD_RANGE_FIRST = 2, CMD_RANGE_MID = 3,
  CMD_RANGE_LAST = 4, CMD_RANGE_ALL = 5, CMD_RANGE_ANY = 6;

let dest_str = "";
const dest_data = newCmdData();

export function newCmdData() {
  return { rlist: new Uint8Array(256), slist: new Uint8Array(64), plist: new Uint8Array(64) };
}

export function config_init(dest) {
  config_set_command_dest(dest);
}

export function config_set_command_dest(str) {
  dest_str = str;
  config_parse_dest(str, dest_data);
  mainwin_update_dest(str);
}

export function config_command_dest() {
  return dest_str;
}

export function config_dest_includes_l1(l1) {
  return dest_data.rlist[l1.rack] && dest_data.slist[l1.slot] && dest_data.plist[l1.partition];
}

/* strtok() over one string */
function tokenizer(s) {
  let pos = 0;

  return delim => {
    while (pos < s.length && delim.includes(s[pos]))
      pos++;
    if (pos >= s.length)
      return null;
    let end = pos;
    while (end < s.length && !delim.includes(s[end]))
      end++;
    const tok = s.slice(pos, end);
    pos = end < s.length ? end + 1 : end;
    return tok;
  };
}

function mark_range(X, n2, n1) {
  if (n2 === n1) {
    X[n2] = CMD_RANGE_ONE;
    return;
  }
  X[n2] = CMD_RANGE_FIRST;
  for (let n = n2 + 1; n < n1; n++)
    X[n] = CMD_RANGE_MID;
  X[n1] = CMD_RANGE_LAST;
}

/* "*", "all", "**" or numbers and n-m ranges separated by commas; nonzero
 * on an error */
function match_range(X, s) {
  let range = 0, n2 = 0;

  X.fill(CMD_RANGE_NONE);
  if (s === "*" || s === "all") {
    X.fill(CMD_RANGE_ALL);
    return 0;
  }
  if (s === "**") {
    X.fill(CMD_RANGE_ANY);
    return 0;
  }
  while (s !== "") {
    const len = /^[0-9]*/.exec(s)[0].length;
    if (len === 0)
      return 1;
    const n1 = parseInt(s, 10);
    if (n1 >= X.length)
      return 1;
    if (s[len] === "-") {
      n2 = n1;
      range = 1;
      s = s.slice(len + 1);
      if (s === "")
        return 1;
      continue;
    }
    if (range) {
      if (n1 < n2)
        return 1;
      mark_range(X, n2, n1);
      range = 0;
    }
    else
      X[n1] = CMD_RANGE_ONE;
    if (s[len] === ",") {
      s = s.slice(len + 1);
      if (s === "")
        return 1;
    }
    else if (len < s.length)    /* (something else after the number) */
      return 1;
    else
      s = "";
  }
  return 0;
}

/* the destination alone, as a command: "*" or "all"; "rack|r <rng>
 * [slot|s <rng>]"; or "partition|p <rng>", and nothing after it */
function match_dest(cd, cmd) {
  let strtok = tokenizer(cmd);
  let tok = strtok(" ");

  if (tok === null)
    return false;
  if (tok === "*" || tok === "all") {
    match_range(cd.rlist, "**");
    match_range(cd.slist, "**");
    cd.plist.fill(0);
  }
  else if (tok === "r" || tok === "rack") {
    tok = strtok(" ");
    if (tok === null || match_range(cd.rlist, tok) !== 0)
      return false;
    tok = strtok(" ");
    if (tok === null)
      return false;
    if (tok !== "s" && tok !== "slot") {
      /* every slot, and the word is given back */
      match_range(cd.slist, "**");
      strtok = tokenizer(cmd);
      strtok(" ");
      strtok(" ");
      cd.plist.fill(0);
    }
    else {
      tok = strtok(" ");
      if (tok === null || match_range(cd.slist, tok) !== 0)
        return false;
      cd.plist.fill(0);
    }
  }
  else if (tok === "p" || tok === "partition") {
    tok = strtok(" ");
    if (tok === null || match_range(cd.plist, tok) !== 0)
      return false;
    cd.rlist.fill(0);
    cd.slist.fill(0);
  }
  else
    return false;
  return strtok("") === null;   /* words left over */
}

export function config_parse_dest(str, data) {
  const cd = newCmdData();

  data.rlist.fill(0);
  data.slist.fill(0);
  data.plist.fill(0);
  if (match_dest(cd, str)) {
    data.rlist.set(cd.rlist);
    data.slist.set(cd.slist);
    data.plist.set(cd.plist);
  }
  if (config_popcnt(data.rlist) === 0) {
    /* a partition destination: every rack and slot */
    data.rlist.fill(5);
    data.slist.fill(5);
  }
  else
    data.plist.fill(5);
}

export function config_popcnt(s, slen = s.length) {
  let c = 0;

  for (let i = 0; i < slen; i++)
    if (s[i])
      c++;
  return c;
}
