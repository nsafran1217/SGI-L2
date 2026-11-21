/*
 * sys_ctrl/l3/webgui/l2select.js
 *
 * New in the modern tree, with no l2gui original (SGI's l2gui picked its
 * L2 once, from --l2 or by discovery): the bar above the panel, naming the
 * L2 l2api is connected to, and its dialog to move l2api to another
 * (POST /api/v1/l2), offering the L2s discovery finds (GET
 * /api/v1/discover). l2api has one connection to one L2, so this moves
 * every page and script using that l2api.
 */

const $ = id => document.getElementById(id);
let current = { host: "", connected: false };

/* an "l2" event, or the answer to a switch */
export function l2select_update(l2) {
  current = l2;
  $("l2host").textContent = l2.host || "(looking for one)";
  $("l2state").textContent = l2.connected ? "connected" : "connecting…";
  $("l2bar").classList.toggle("down", !l2.connected);
}

function message(text) {
  $("l2msg").textContent = text;
}

async function api(path, options) {
  let r, reply;

  try {
    r = await fetch(path, options);
    reply = await r.json();
  }
  catch (e) {
    throw new Error("can't reach l2api");
  }
  if (!r.ok)
    throw new Error(reply.error || `HTTP ${r.status}`);
  return reply;
}

function found_row(l2) {
  const b = document.createElement("button");
  const ip = document.createElement("strong");
  const about = document.createElement("span");
  const facts = [`rack ${l2.rack}`];

  if (l2.sysname)
    facts.push(l2.sysname);
  if (l2.serial)
    facts.push(`SSN ${l2.serial}`);
  if (l2.version)
    facts.push(l2.version);
  b.type = "button";
  b.className = "l2found";
  ip.textContent = l2.ip;
  about.textContent = facts.join(" · ");
  b.append(ip, about);
  if (l2.ip === current.host)
    b.classList.add("current");
  b.onclick = () => {
    $("l2input").value = l2.ip;
    $("l2input").focus();
  };
  return b;
}

async function discover() {
  const list = $("l2list");

  list.replaceChildren();
  $("l2find").disabled = true;
  message("Looking for L2s on the network…");
  try {
    const reply = await api("api/v1/discover");
    list.append(...reply.l2s.map(found_row));
    message(reply.l2s.length ? "" : "No L2s answered. Enter a host name or address.");
  }
  catch (e) {
    message(`Can't look for L2s: ${e.message}`);
  }
  finally {
    $("l2find").disabled = false;
  }
}

async function connect(ev) {
  const host = $("l2input").value.trim();

  ev.preventDefault();
  if (host === "") {
    message("Enter a host name or address.");
    return;
  }
  $("l2connect").disabled = true;
  message(`Connecting to ${host}…`);
  try {
    l2select_update(await api("api/v1/l2", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ host }),
    }));
    $("l2dialog").close();
  }
  catch (e) {
    message(`Can't switch to ${host}: ${e.message}`);
  }
  finally {
    $("l2connect").disabled = false;
  }
}

export function l2select_init() {
  $("l2change").onclick = () => {
    $("l2input").value = current.host;
    $("l2dialog").showModal();
    discover();
  };
  $("l2find").onclick = discover;
  $("l2cancel").onclick = () => $("l2dialog").close();
  $("l2form").addEventListener("submit", connect);
}
