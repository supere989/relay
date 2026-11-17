/* Browser acceptance runner only; this is not a product service/backend. */
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const http = require("node:http");
const os = require("node:os");
const {chromium} = require("playwright");

async function main() {
  const appRoot = path.resolve(process.env.MANAGER_UI_DIR);
  const fixtures = JSON.parse(fs.readFileSync(process.env.MANAGER_UI_FIXTURES, "utf8"));
  const resultPath = process.env.MANAGER_UI_RESULT;
  const bridge = process.env.MANAGER_REAL_BRIDGE_URL || null;
  if (bridge && !/^http:\/\/127\.0\.0\.1:[0-9]+$/.test(bridge)) throw new Error("bridge must be task loopback only");
  const checks = [], violations = [], requests = [];
  const server = http.createServer((req, res) => {
    const target = path.resolve(appRoot, "." + new URL(req.url, "http://localhost").pathname);
    if (!target.startsWith(appRoot + path.sep) || !fs.existsSync(target) || !fs.statSync(target).isFile()) { res.writeHead(404).end(); return; }
    const extension = path.extname(target);
    res.setHeader("Content-Type", ({".html":"text/html", ".js":"application/javascript", ".css":"text/css", ".svg":"image/svg+xml", ".png":"image/png"})[extension] || "application/octet-stream");
    res.end(fs.readFileSync(target));
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const origin = "http://127.0.0.1:" + server.address().port;
  let browser = null;
  const browserPrivate = fs.mkdtempSync(path.join(os.tmpdir(), "archive-browser-"));
  const browserConfig = path.join(browserPrivate, "config"), browserCache = path.join(browserPrivate, "cache");
  fs.mkdirSync(browserConfig, {mode: 0o700}); fs.mkdirSync(browserCache, {mode: 0o700});
  async function pageFor(query = "", unsupported = false, clock = null) {
    const context = await browser.newContext({viewport: {width: 320, height: 740}});
    await context.route("**/*", route => {
      const url = route.request().url(); requests.push(url);
      if (url.startsWith(origin + "/")) return route.continue();
      violations.push("external_request"); return route.abort();
    });
    if (unsupported) await context.addInitScript(() => { window.Worker = function () { throw new Error("unsupported fixture"); }; });
    const page = await context.newPage();
    if (clock !== null) await page.clock.install({time: clock * 1000});
    await page.goto(origin + "/index.html" + query);
    return {context, page};
  }
  async function deliver(page, envelope) {
    await page.evaluate(value => window.__archiveSdk.deliver(value), envelope);
  }
  async function waitText(page, selector, text) {
    await page.waitForFunction(({selector, text}) => document.querySelector(selector).textContent.includes(text), {selector, text});
  }
  async function sent(page, count) {
    await page.waitForFunction(count => window.__archiveSdk && window.__archiveSdk.sent.length >= count, count);
    return page.evaluate(() => window.__archiveSdk.sent.map(item => item.payload));
  }
  async function relay(command) {
    const response = await fetch(bridge + "/command", {method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify({command}), signal: AbortSignal.timeout(180000)});
    assert.equal(response.status, 200);
    const value = await response.json(); assert(value.response); return value;
  }
  async function lostAckPage(queued = false) {
    const test = await pageFor("?fixture=1", false, fixtures.fixture_stamp);
    const first = (await sent(test.page, 1))[0];
    assert.equal(first.id, "3".repeat(32)); assert.equal(first.action, "status");
    await deliver(test.page, fixtures.lost_start);
    await waitText(test.page, "#connection", "Status verified");
    await test.page.locator("#pause").click();
    const command = (await sent(test.page, 2))[1];
    assert.equal(command.id, "4".repeat(32)); assert.equal(command.action, "pause");
    assert(await test.page.locator("#pause").isDisabled());
    if (queued) {
      await deliver(test.page, fixtures.lost_queued);
      await waitText(test.page, "#feedback", "not yet verified");
      assert(await test.page.locator("#pause").isDisabled(), "queued is not terminal or permission for a second mutation");
    }
    await test.page.clock.setSystemTime((fixtures.fixture_stamp + 30) * 1000);
    await test.page.clock.runFor(1100);
    await test.page.locator("#refresh").click();
    const refresh = (await sent(test.page, 3))[2];
    assert.equal(refresh.id, "5".repeat(32)); assert.equal(refresh.action, "refresh");
    return test;
  }
  try {
    browser = await chromium.launch({headless: true, executablePath: process.env.MANAGER_BROWSER_EXECUTABLE || undefined,
      env: {...process.env, XDG_CONFIG_HOME: browserConfig, XDG_CACHE_HOME: browserCache}});
    if (process.env.MANAGER_LOST_ACK_BASELINE === "1") {
      assert(!bridge);
      const test = await lostAckPage();
      await deliver(test.page, fixtures.lost_fresh);
      await waitText(test.page, "#connection", "Status verified");
      assert(await test.page.locator("#pause").isDisabled(), "old staged UI no longer reproduces permanent pending block");
      const messages = await test.page.evaluate(() => window.__archiveSdk.sent.map(item => item.payload));
      assert.equal(messages.filter(item => item.action === "pause").length, 1);
      checks.push("old staged UI reproduced: expired lost acknowledgement remains blocked after correlated fresh read-only status; no mutation replay");
      await test.context.close();
    } else if (bridge) {
      const {context, page} = await pageFor();
      const initial = (await sent(page, 1))[0];
      assert.equal(initial.action, "status");
      await deliver(page, (await relay(initial)).response);
      await waitText(page, "#connection", "Status verified");
      await page.locator("#pause").click();
      const pause = (await sent(page, 2))[1]; assert.equal(pause.action, "pause");
      assert(!await page.locator("#feedback").textContent().then(text => text.includes("confirmed this change")));
      const outcome = await relay(pause);
      await deliver(page, outcome.response);
      await waitText(page, "#feedback", "confirmed this change");
      await waitText(page, "#archive-state", "turned off");
      assert.equal(outcome.binding_enabled, false, "actual facade binding was not committed off");
      checks.push("actual packaged UI pause -> real 2.69 encrypted SMTP/IMAP update -> actual facade -> signed confirmation");
      const finished = await fetch(bridge + "/finish", {method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify({complete:true}), signal: AbortSignal.timeout(10000)});
      assert.equal(finished.status, 200);
      assert.equal((await finished.json()).complete, true);
      checks.push("actual SDK restart preserves both identities and recorded command without applying pause twice");
      await context.close();
    } else {
      const {context, page} = await pageFor("?fixture=1&history=1&interval=200");
      await sent(page, 1);
      await waitText(page, "#connection", "Earlier status");
      assert(await page.locator("#pause").isDisabled());
      checks.push("historical signed state is stale and never confirms a new request");
      await deliver(page, fixtures.snapshot);
      await waitText(page, "#connection", "Status verified");
      assert.equal(await page.locator("#mailbox option").count(), 2);
      assert.equal(await page.locator('label[for="mailbox"]').textContent(), "Mailbox");
      assert(await page.locator("#pause").isEnabled());
      assert(await page.locator("#resume").isDisabled());
      assert(await page.locator("#updated").textContent().then(text => text.startsWith("Status as of: ")));
      assert.equal(await page.locator("#jobs li").first().locator("p").first().textContent(), "Retry needed");
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
      await page.locator("#refresh").focus(); await page.keyboard.press("Tab");
      assert.equal(await page.evaluate(() => document.activeElement.tagName), "SUMMARY");
      checks.push("mobile320 layout, mailbox selection label and keyboard focus");
      assert(await page.locator("#coverage").textContent().then(text => text.includes("incomplete")));
      assert(await page.locator("footer").textContent().then(text => text.includes("not a complete")));
      assert.equal(await page.locator("#unresolved").textContent(), "2");
      assert.equal(await page.locator("#eligible-unresolved").textContent(), "1");
      assert.equal(await page.locator("#held-unresolved").textContent(), "1");
      assert(await page.locator("#jobs-omitted").textContent().then(text => text.includes("3 additional")));
      assert(await page.locator("#archive-help").textContent().then(text => text.includes("on hold")));
      assert.equal(await page.locator("#verified-files").textContent(), "2");
      checks.push("verified files and partial coverage are distinguished from queue state");
      if (process.env.MANAGER_UI_SCREENSHOT) {
        assert(path.isAbsolute(process.env.MANAGER_UI_SCREENSHOT));
        await page.screenshot({path: process.env.MANAGER_UI_SCREENSHOT, fullPage: true});
        checks.push("actual packaged mobile preview with synthetic signed state and no pairing secrets");
      }
      await page.locator("#pause").click();
      const messages = await sent(page, 2); assert.equal(messages[1].action, "pause");
      assert(messages[1].lease && messages[1].binding);
      assert.equal(messages[1].id, "4".repeat(32));
      const times = await page.evaluate(() => window.__archiveSdk.sent.map(item => item.at));
      assert(times[1] - times[0] >= 180, "sendUpdateInterval was bypassed");
      assert(await page.locator("#feedback").textContent().then(text => text.includes("Waiting for the bot")));
      await deliver(page, fixtures.forged);
      await waitText(page, "#feedback", "unverified");
      assert.equal(await page.locator("#verified-files").textContent(), "2");
      checks.push("peer-forged success rejected before authoritative rendering");
      const verificationBeforeBudget = await page.locator("#verification-events").textContent();
      assert(Buffer.byteLength(JSON.stringify({payload: fixtures.raw_over_budget}), "utf8") < 32768);
      await deliver(page, fixtures.raw_over_budget);
      await page.waitForFunction(before => document.querySelector("#verification-events").textContent !== before, verificationBeforeBudget);
      await waitText(page, "#feedback", "unverified");
      assert.equal(await page.locator("#verified-files").textContent(), "2");
      checks.push("validly signed raw-over-budget response rejected within whole-wire transport limit");
      await deliver(page, fixtures.queued);
      await waitText(page, "#feedback", "not yet verified");
      assert.equal(await page.locator("#queued-jobs").textContent(), "1");
      assert.equal(await page.locator("#verified-files").textContent(), "2");
      checks.push("persisted queued acknowledgement does not claim confirmed or verified work");
      // A later committed response can report the same requested change even
      // after the accepted command left the pending map. State stays signed.
      await deliver(page, fixtures.confirmed);
      await waitText(page, "#archive-state", "turned off");
      await waitText(page, "#feedback", "confirmed this change");
      const state = await page.locator("#archive-state").textContent();
      await deliver(page, fixtures.snapshot); await waitText(page, "#feedback", "older");
      assert.equal(await page.locator("#archive-state").textContent(), state);
      await deliver(page, fixtures.confirmed);
      assert.equal(await page.locator("#archive-state").textContent(), state);
      await deliver(page, fixtures.expired); await waitText(page, "#feedback", "expired");
      await deliver(page, fixtures.wrong_instance); await waitText(page, "#feedback", "unverified");
      assert.equal(await page.locator("#archive-state").textContent(), state);
      checks.push("reordered duplicate expired and wrong-instance updates cannot rewind state");
      await deliver(page, fixtures.unmatched_replay);
      await waitText(page, "#connection", "Earlier status");
      assert(await page.locator("#pause").isDisabled());
      checks.push("valid unmatched live replay cannot confirm an online check or enable controls");
      await context.close();
      const pairingPage = await pageFor("?fixture=1");
      await sent(pairingPage.page, 1);
      await deliver(pairingPage.page, fixtures.pairing);
      await waitText(pairingPage.page, "#comparison", "628194");
      const url = await pairingPage.page.locator("#portal-url").inputValue();
      assert(url.startsWith(fixtures.context.portal_origin + "/"));
      assert(!url.includes("628194"), "comparison channel leaked into portal URL");
      await pairingPage.page.locator("#refresh").click();
      await sent(pairingPage.page, 2);
      await deliver(pairingPage.page, fixtures.intent);
      await pairingPage.page.locator("#pair-confirm").click();
      const pairCommand = (await sent(pairingPage.page, 3))[2];
      assert.equal(pairCommand.action, "pair_confirm"); assert.equal(pairCommand.binding, null);
      assert(pairCommand.lease && pairCommand.args.intent && pairCommand.args.challenge);
      await pairingPage.page.locator("#copy-url").click();
      assert.equal(await pairingPage.page.evaluate(() => document.activeElement.id), "portal-url");
      checks.push("pair comparison remains separate; signed intent requires purpose lease and visible portal copy fallback");
      await pairingPage.context.close();
      const lostPair = await pageFor("?fixture=1");
      assert.equal((await sent(lostPair.page, 1))[0].action, "status");
      // Neither the initial status nor pair_start receives an acknowledgement;
      // pair_start was sent before any snapshot, so priorExpires is null.
      await lostPair.page.locator("#pair-start").click();
      const start = (await sent(lostPair.page, 2))[1];
      assert.equal(start.action, "pair_start"); assert.equal(start.binding, null); assert.equal(start.lease, null);
      await lostPair.page.locator("#refresh").click();
      const pairRead = (await sent(lostPair.page, 3))[2];
      assert.equal(pairRead.action, "refresh"); assert.equal(pairRead.id, "5".repeat(32));
      await deliver(lostPair.page, fixtures.lost_pair_url);
      await waitText(lostPair.page, "#comparison", "628194");
      assert(await lostPair.page.locator("#portal-url").inputValue().then(url => url.startsWith(fixtures.context.portal_origin) && !url.includes("628194")));
      await lostPair.page.locator("#refresh").click();
      const intentRead = (await sent(lostPair.page, 4))[3];
      assert.equal(intentRead.action, "refresh"); assert.equal(intentRead.id, "6".repeat(32));
      await deliver(lostPair.page, fixtures.lost_pair_intent);
      await waitText(lostPair.page, "#pair-instruction", "Confirm only if");
      assert(await lostPair.page.locator("#pair-confirm").isEnabled());
      await lostPair.page.locator("#pair-confirm").click();
      const confirmation = (await sent(lostPair.page, 5))[4];
      assert.equal(confirmation.action, "pair_confirm"); assert.equal(confirmation.binding, null);
      assert.equal(confirmation.generation, 0); assert.equal(confirmation.link_revision, 0);
      assert.equal(confirmation.lease, "c".repeat(43));
      assert.deepEqual(confirmation.args, {challenge: "7".repeat(32), intent: "8".repeat(32)});
      assert(await lostPair.page.locator("#pair-confirm").isDisabled(), "actual confirmation must retain its pending mutation guard");
      const pairCommands = await lostPair.page.evaluate(() => window.__archiveSdk.sent.map(item => item.payload));
      assert.equal(pairCommands.filter(item => item.action === "pair_start").length, 1);
      assert.equal(pairCommands.filter(item => item.action === "pair_confirm").length, 1);
      assert(!await lostPair.page.locator("#feedback").textContent().then(text => text.includes("confirmed this change")));
      checks.push("lost initial status and pair_start acknowledgements cannot block a fresh signed purpose-leased pairing confirmation; real confirmation remains pending");
      await lostPair.context.close();
      const unavailable = await pageFor("", true);
      await waitText(unavailable.page, "#connection", "cannot run the local");
      assert(await unavailable.page.locator("#mailbox-panel").isHidden());
      assert(await unavailable.page.locator("#pair-panel").isHidden());
      assert(await unavailable.page.locator("#refresh").isDisabled());
      assert.equal(await unavailable.page.locator("#portal-url").inputValue(), fixtures.context.portal_origin);
      checks.push("unsupported worker fails closed with only fixed trusted portal fallback");
      await unavailable.context.close();
      for (const action of ["resume", "reconnect", "recovery", "retry", "unlink"]) {
        const control = await pageFor("?fixture=1");
        await sent(control.page, 1);
        await deliver(control.page, action === "resume" ? fixtures.off_snapshot : fixtures.snapshot);
        await waitText(control.page, "#connection", "Status verified");
        if (action === "resume") assert(await control.page.locator("#pause").isDisabled());
        if (action === "retry") await control.page.locator("button[data-retry]").first().click();
        else if (action === "unlink") { await control.page.locator("#mailbox-panel details summary").click(); await control.page.locator("#unlink").click(); }
        else await control.page.locator("#" + action).click();
        const command = (await sent(control.page, 2))[1];
        assert.equal(command.action, action); assert.equal(command.binding, "4".repeat(32));
        assert.equal(command.generation, action === "resume" ? 2 : 1); assert.equal(command.link_revision, action === "resume" ? 3 : 2); assert(command.lease);
        if (action === "retry") assert.equal(command.args.job, "6".repeat(32));
        assert(await control.page.locator("#feedback").textContent().then(text => text.includes("Waiting for the bot")));
        assert(await control.page.locator("#archive-state").textContent().then(text => text.includes(action === "resume" ? "turned off" : "enabled")), "unacknowledged control changed authoritative UI state");
        checks.push(action + " emits a purpose-leased revision-bound request without optimistic success");
        await control.context.close();
      }
      const limited = await pageFor("?fixture=1&maxsize=16");
      await waitText(limited.page, "#feedback", "exceeds your client's message limit");
      assert.equal(await limited.page.evaluate(() => window.__archiveSdk.sent.length), 0);
      checks.push("advertised sendUpdateMaxSize is respected without splitting authority-bearing commands");
      await limited.context.close();
      const unknown = await pageFor("?fixture=1");
      await sent(unknown.page, 1);
      await deliver(unknown.page, fixtures.unknown_snapshot);
      await waitText(unknown.page, "#connection", "Status verified");
      assert(await unknown.page.locator("#coverage").textContent().then(text => text.includes("No verified archive yet") && !text.includes("Verified capture windows")));
      assert.equal(await unknown.page.locator("#last-verified").textContent(), "No verified archive yet");
      assert.equal(await unknown.page.locator("#verified-files").textContent(), "0");
      assert.equal(await unknown.page.locator("#eligible-unresolved").textContent(), "0");
      assert.equal(await unknown.page.locator("#held-unresolved").textContent(), "0");
      checks.push("zero unresolved before any receipt remains unknown and never claims verified coverage");
      await unknown.context.close();
      const maximum = await pageFor("?fixture=1");
      await sent(maximum.page, 1);
      assert(Buffer.byteLength(JSON.stringify({payload: fixtures.maximum_snapshot}), "utf8") < 32768);
      await deliver(maximum.page, fixtures.maximum_snapshot);
      await waitText(maximum.page, "#connection", "Status verified");
      assert.equal(await maximum.page.locator("#mailbox option").count(), 16);
      assert(fixtures.maximum_jobs_omitted > 0);
      const maximumDocument = JSON.parse(Buffer.from(fixtures.maximum_snapshot.payload, "base64url").toString("utf8"));
      for (let index = 0; index < 16; index++) {
        await maximum.page.locator("#mailbox").selectOption({index});
        assert(await maximum.page.locator("#pause").isEnabled());
        assert(await maximum.page.locator("#resume").isDisabled());
        assert(await maximum.page.locator("#reconnect").isEnabled());
        assert(await maximum.page.locator("#recovery").isEnabled());
        assert.equal(await maximum.page.locator("#jobs-omitted").isVisible(), maximumDocument.bindings[index].jobs_omitted > 0);
      }
      assert(await maximum.page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
      checks.push("maximum16-mailbox state with real generated leases fits full wire and preserves every selection/control with visible omissions");
      await maximum.context.close();
      for (const [name, queued] of [["lost_fresh", false], ["lost_fresh", true], ["lost_generation", false], ["lost_revision", false], ["lost_absent", false]]) {
        const test = await lostAckPage(queued);
        await deliver(test.page, fixtures[name]);
        await waitText(test.page, "#connection", "Status verified");
        await waitText(test.page, "#feedback", "outcome is unknown");
        assert(await test.page.locator("#pause").isEnabled(), "fresh read-only proof should make old mutation inapplicable");
        assert(!await test.page.locator("#feedback").textContent().then(text => text.includes("confirmed this change")));
        const commands = await test.page.evaluate(() => window.__archiveSdk.sent.map(item => item.payload));
        assert.equal(commands.length, 3); assert.equal(commands.filter(item => item.action === "pause").length, 1);
        // An old response cannot retroactively correlate with a command we
        // safely retired as unknown, or confirm a new request on its behalf.
        await deliver(test.page, fixtures.lost_late);
        await waitText(test.page, "#connection", "Earlier status");
        assert(await test.page.locator("#pause").isDisabled());
        assert(await test.page.locator("#feedback").textContent().then(text => text.includes("outcome is unknown") && !text.includes("confirmed this change")));
        checks.push((queued ? "queued acknowledgement then lost terminal reply" : "lost acknowledgement " + name) + ": only fresh read-only inapplicability proof releases controls, preserves unknown outcome, never replays or accepts late success");
        await test.context.close();
      }
      for (const name of ["lost_applicable", "lost_boundary"]) {
        const test = await lostAckPage();
        await deliver(test.page, fixtures.lost_history);
        await waitText(test.page, "#feedback", "older");
        assert(await test.page.locator("#pause").isDisabled());
        await deliver(test.page, fixtures.lost_unmatched);
        await waitText(test.page, "#connection", "Earlier status");
        assert(await test.page.locator("#pause").isDisabled());
        await deliver(test.page, fixtures[name]);
        await waitText(test.page, "#connection", "Status verified");
        await waitText(test.page, "#feedback", "outcome is unknown");
        assert(await test.page.locator("#pause").isDisabled(), "global revision/client time/rounding boundary cannot expire a still-applicable lease");
        await test.page.clock.setSystemTime((fixtures.fixture_stamp + 150) * 1000);
        await test.page.clock.runFor(1100);
        assert(await test.page.locator("#pause").isDisabled(), "advancing only the client clock must not unblock a mutation");
        await test.page.locator("#refresh").click();
        const command = (await sent(test.page, 4))[3]; assert.equal(command.action, "refresh"); assert.equal(command.id, "6".repeat(32));
        const original = JSON.parse(Buffer.from(fixtures.lost_start.payload, "base64url").toString("utf8"));
        const followup = JSON.parse(Buffer.from(fixtures.lost_followup.payload, "base64url").toString("utf8"));
        assert.equal(followup.command_id, command.id);
        assert(followup.issued_at > original.expires_at + 1, "followup must prove expiry of the original pending lease with margin");
        await deliver(test.page, fixtures.lost_followup);
        // "Status verified" is already visible for the previous response.
        // Wait for this distinct signed timestamp after the real worker runs.
        await test.page.waitForFunction(issued => document.querySelector("#updated").textContent === "Status as of: " + new Date(issued * 1000).toLocaleString(), followup.issued_at);
        await waitText(test.page, "#connection", "Status verified");
        assert(await test.page.locator("#pause").isEnabled());
        assert(await test.page.locator("#feedback").textContent().then(text => text.includes("outcome is unknown")));
        const commands = await test.page.evaluate(() => window.__archiveSdk.sent.map(item => item.payload));
        assert.equal(commands.filter(item => item.action === "pause").length, 1);
        checks.push(name + ": historical/unmatched responses, global revision and client clock cannot release a possible mutation; a later correlated server proof can");
        await test.context.close();
      }
    }
    assert.equal(violations.length, 0);
    assert(requests.some(url => url.endsWith("/verify-worker.js")), "actual packaged verification worker was not requested");
    assert(requests.some(url => url.endsWith("/vendor/nacl-fast.min.js")), "pinned local verifier was not requested");
    checks.push("actual packaged local worker and verifier; no external network request");
    const result = {state: "passed", checks, passed: checks.length, external_requests: violations.length, real_rpc_bridge: !!bridge, app_sha256: fixtures.app_sha256};
    if (resultPath) fs.writeFileSync(resultPath, JSON.stringify(result, null, 2));
    console.log(JSON.stringify(result));
  } catch (error) {
    if (resultPath) fs.writeFileSync(resultPath, JSON.stringify({state: "failed", passed: checks.length, checks, reason: error.name, external_requests: violations.length}, null, 2));
    throw error;
  } finally {
    try { if (browser) await browser.close(); } finally { await new Promise(resolve => server.close(resolve)); }
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
