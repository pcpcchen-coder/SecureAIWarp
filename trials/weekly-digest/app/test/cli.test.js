// 端對端測試：使用真正的 @anthropic-ai/sdk，但 baseURL 指向本機假 API（127.0.0.1），不連外網。
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import { main, parseCli } from "../src/cli.js";
import { createClient, askClaude, FALLBACK_BETA } from "../src/claude.js";
import { makeTempDir, writeNote, startMockApi, memoryStream } from "./helpers.js";

const NOW = new Date(2026, 10, 26, 15, 0, 0);

function responder(body) {
  const sys = body.system;
  if (sys.includes("本週總結")) return { text: "本週完成登入改版規劃。" };
  return { text: "#### 重點\n- 討論登入流程\n\n#### 待辦事項\n| 待辦事項 | 負責人 | 期限 |\n|---|---|---|\n| 畫流程圖 | 小明 | 11/28 |" };
}

test("askClaude 以串流呼叫 Messages API，帶正確的模型、beta 與備援參數", async () => {
  const api = await startMockApi(() => ({ text: "你好，世界" }));
  try {
    const client = createClient({ baseURL: api.url, apiKey: "sk-ant-test", maxRetries: 0 });
    const text = await askClaude(client, { system: "S", prompt: "P" });
    assert.equal(text, "你好，世界");
    const [r] = api.requests;
    assert.equal(r.method, "POST");
    assert.match(r.url, /^\/v1\/messages/);
    // SDK 1.x 以 Authorization: Bearer 傳送 API 金鑰（舊版用 x-api-key），兩者 API 都接受
    const sentKey = r.headers["x-api-key"] ?? r.headers.authorization?.replace(/^Bearer /, "");
    assert.equal(sentKey, "sk-ant-test");
    assert.ok(r.headers["anthropic-version"], "帶 anthropic-version 標頭");
    assert.match(r.headers["anthropic-beta"], new RegExp(FALLBACK_BETA));
    assert.equal(r.body.model, "claude-opus-5-5");
    assert.equal(r.body.stream, true);
    assert.equal(r.body.fallbacks, "default");
    assert.deepEqual(r.body.output_config, { effort: "medium" });
    assert.equal(r.body.thinking, undefined, "Opus 5.5 不送 thinking 設定（預設即 adaptive）");
    assert.deepEqual(r.body.messages, [{ role: "user", content: "P" }]);
  } finally {
    await api.close();
  }
});

test("askClaude 在 --no-fallbacks 時不帶 beta 與 fallbacks", async () => {
  const api = await startMockApi(() => ({ text: "ok" }));
  try {
    const client = createClient({ baseURL: api.url, apiKey: "sk-ant-test", maxRetries: 0 });
    await askClaude(client, { system: "S", prompt: "P", fallbacks: false });
    const [r] = api.requests;
    assert.equal(r.body.fallbacks, undefined);
    assert.equal(r.headers["anthropic-beta"], undefined);
  } finally {
    await api.close();
  }
});

test("askClaude 遇到拒答或 max_tokens 截斷時拋出明確錯誤", async () => {
  let mode = "refusal";
  const api = await startMockApi(() =>
    mode === "refusal"
      ? { text: "", stop_reason: "refusal", stop_details: { type: "refusal", category: "cyber", explanation: null } }
      : { text: "截斷的", stop_reason: "max_tokens" },
  );
  try {
    const client = createClient({ baseURL: api.url, apiKey: "sk-ant-test", maxRetries: 0 });
    await assert.rejects(askClaude(client, { system: "S", prompt: "P" }), /拒絕/);
    mode = "max";
    await assert.rejects(askClaude(client, { system: "S", prompt: "P" }), /max_tokens/);
  } finally {
    await api.close();
  }
});

test("CLI 端對端：讀資料夾、呼叫 API、寫出週報", async () => {
  const dir = await makeTempDir();
  const api = await startMockApi(responder);
  try {
    await writeNote(dir, "notes/2026-11-24-登入改版.md", "# 登入改版討論\n小明負責畫流程圖。");
    await writeNote(dir, "notes/2026-11-25-週會.txt", "週會：決議下週上線。");
    await writeNote(dir, "notes/2026-11-01-舊.md", "不該被讀到");
    const out = path.join(dir, "out", "digest.md");
    const stderr = memoryStream();
    const client = createClient({ baseURL: api.url, apiKey: "sk-ant-test", maxRetries: 0 });

    const code = await main([path.join(dir, "notes"), "-o", out], { client, now: NOW, stderr, stdout: memoryStream() });
    assert.equal(code, 0, stderr.text);
    assert.equal(api.requests.length, 3, "2 場會議 + 1 次總結");
    assert.ok(!api.requests.some((r) => JSON.stringify(r.body).includes("不該被讀到")));

    const md = await fs.readFile(out, "utf8");
    assert.match(md, /# 會議週報（2026-11-20 ～ 2026-11-26）/);
    assert.match(md, /### 登入改版討論（2026-11-24）/);
    assert.match(md, /\| 畫流程圖 \| 小明 \| 11\/28 \|/);
    assert.match(md, /## 本週總結\n\n本週完成登入改版規劃。/);
  } finally {
    await api.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("CLI：API 回傳 401 時顯示金鑰錯誤並回傳非零", async () => {
  const dir = await makeTempDir();
  const api = await startMockApi(() => ({ status: 401, error: { type: "authentication_error", message: "invalid x-api-key" } }));
  try {
    await writeNote(dir, "2026-11-24-a.md", "內容");
    const stderr = memoryStream();
    const client = createClient({ baseURL: api.url, apiKey: "bad", maxRetries: 0 });
    const code = await main([dir, "-o", path.join(dir, "x.md")], { client, now: NOW, stderr, stdout: memoryStream() });
    assert.equal(code, 1);
    assert.match(stderr.text, /金鑰無效/);
  } finally {
    await api.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("CLI：沒有金鑰時不發請求並提示設定方式", async () => {
  const dir = await makeTempDir();
  try {
    await writeNote(dir, "2026-11-24-a.md", "內容");
    const stderr = memoryStream();
    const code = await main([dir], { env: {}, now: NOW, stderr, stdout: memoryStream() });
    assert.equal(code, 2);
    assert.match(stderr.text, /ANTHROPIC_API_KEY/);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("CLI --dry-run 列出檔案與分段，不呼叫 API", async () => {
  const dir = await makeTempDir();
  try {
    await writeNote(dir, "2026-11-24-長會議.md", "很長的內容。\n".repeat(200));
    const stdout = memoryStream();
    const code = await main([dir, "--dry-run", "--chunk-chars", "500"], { env: {}, now: NOW, stderr: memoryStream(), stdout });
    assert.equal(code, 0);
    assert.match(stdout.text, /2026-11-24-長會議\.md .* 段/);
    assert.doesNotMatch(stdout.text, / 1 段/);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("CLI 參數驗證", async () => {
  assert.equal(parseCli(["d"]).days, 7);
  assert.equal(parseCli(["d", "--no-fallbacks"]).fallbacks, false);
  assert.throws(() => parseCli(["d", "--days", "0"]), /--days/);
  assert.throws(() => parseCli(["d", "--effort", "huge"]), /--effort/);
  const stderr = memoryStream();
  assert.equal(await main([], { stderr, stdout: memoryStream() }), 2);
  const stdout = memoryStream();
  assert.equal(await main(["--help"], { stdout, stderr: memoryStream() }), 0);
  assert.match(stdout.text, /用法/);
});
