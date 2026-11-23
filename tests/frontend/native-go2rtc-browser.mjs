// A new isolated headless profile with a synthetic microphone. No HA session.
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import assert from "node:assert/strict";

const [binary, profile, target] = process.argv.slice(2);
const url = new URL(target);
assert.equal(url.hostname, "127.0.0.1");
const chrome = spawn(binary, [
  "--headless", "--no-first-run", "--disable-gpu", "--disable-background-networking",
  "--disable-component-update", "--disable-sync", "--no-default-browser-check",
  "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
  "--use-fake-device-for-media-stream", "--use-fake-ui-for-media-stream",
  "--autoplay-policy=no-user-gesture-required", "--remote-debugging-pipe",
  `--user-data-dir=${profile}`, "about:blank",
], { stdio: ["ignore", "ignore", "ignore", "pipe", "pipe"] });
process.once("SIGTERM", () => {
  chrome.kill("SIGTERM");
  process.exit(143);
});
let partial = "", sequence = 0;
const pending = new Map();
function disconnected() {
  for (const resolve of pending.values()) resolve({ error: { message: "Browser closed" } });
  pending.clear();
}
chrome.on("error", disconnected);
chrome.on("exit", disconnected);
chrome.stdio[3].on("error", disconnected);
chrome.stdio[4].setEncoding("utf8");
chrome.stdio[4].on("data", (chunk) => {
  const lines = (partial + chunk).split("\0");
  partial = lines.pop();
  for (const line of lines) {
    if (!line) continue;
    const message = JSON.parse(line);
    pending.get(message.id)?.(message);
    pending.delete(message.id);
  }
});
async function cdp(method, params = {}, sessionId) {
  const id = ++sequence;
  const request = new Promise(resolve => pending.set(id, resolve));
  chrome.stdio[3].write(JSON.stringify({ id, method, params, sessionId }) + "\0");
  const deadline = AbortSignal.timeout(7000);
  const result = await Promise.race([request, sleep(7500, null, { ref: false })]);
  pending.delete(id);
  if (!result || result.error || deadline.aborted) throw Error(`Browser ${method}: ${result?.error?.message || "timeout"}`);
  return result.result;
}
try {
  const { targetId } = await cdp("Target.createTarget", { url: "about:blank" });
  const { sessionId } = await cdp("Target.attachToTarget", { targetId, flatten: true });
  await cdp("Page.navigate", { url: url.href }, sessionId);
  let result;
  for (let i = 0; i < 180 && !result; i++) {
    const payload = await cdp("Runtime.evaluate", {
      expression: "document.body?.dataset?.result", returnByValue: true,
    }, sessionId);
    result = payload.result?.value;
    if (!result) await sleep(100);
  }
  assert.ok(result, "No result from browser fixture");
  const outcome = JSON.parse(result);
  console.log(JSON.stringify(outcome));
  if (!outcome.ok) process.exitCode = 1;
} finally {
  chrome.kill("SIGTERM");
}
