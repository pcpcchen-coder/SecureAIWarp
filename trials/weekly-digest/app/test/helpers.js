// 測試輔助：暫存資料夾、以及模擬 Anthropic Messages API 串流回應的本機 HTTP 伺服器。
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import http from "node:http";

export async function makeTempDir(prefix = "weekly-digest-test-") {
  return fs.mkdtemp(path.join(os.tmpdir(), prefix));
}

export async function writeNote(dir, name, content, mtime) {
  const file = path.join(dir, name);
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.writeFile(file, content, "utf8");
  if (mtime) await fs.utimes(file, mtime, mtime);
  return file;
}

function sse(event, data) {
  return `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
}

/**
 * 啟動只監聽 127.0.0.1 的假 API。responder(body, req) 回傳
 * { text, stop_reason?, status?, error? }。所有收到的請求都記錄在 requests。
 */
export async function startMockApi(responder) {
  const requests = [];
  const server = http.createServer(async (req, res) => {
    let raw = "";
    for await (const chunk of req) raw += chunk;
    const body = raw ? JSON.parse(raw) : null;
    requests.push({ method: req.method, url: req.url, headers: req.headers, body });

    const r = await responder(body, req);
    if (r.status && r.status !== 200) {
      res.writeHead(r.status, { "content-type": "application/json" });
      res.end(JSON.stringify({ type: "error", error: r.error ?? { type: "api_error", message: "mock error" } }));
      return;
    }
    res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
    const id = `msg_mock_${requests.length}`;
    res.write(
      sse("message_start", {
        type: "message_start",
        message: {
          id,
          type: "message",
          role: "assistant",
          model: body?.model ?? "claude-opus-5-5",
          content: [],
          stop_reason: null,
          stop_sequence: null,
          usage: { input_tokens: 10, output_tokens: 1 },
        },
      }),
    );
    res.write(sse("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } }));
    // 分兩次送出文字，確認串流累積正確
    const text = r.text ?? "";
    const mid = Math.floor(text.length / 2);
    for (const part of [text.slice(0, mid), text.slice(mid)]) {
      res.write(sse("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: part } }));
    }
    res.write(sse("content_block_stop", { type: "content_block_stop", index: 0 }));
    res.write(
      sse("message_delta", {
        type: "message_delta",
        delta: { stop_reason: r.stop_reason ?? "end_turn", stop_sequence: null, stop_details: r.stop_details ?? null },
        usage: { output_tokens: 20 },
      }),
    );
    res.write(sse("message_stop", { type: "message_stop" }));
    res.end();
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  return {
    url: `http://127.0.0.1:${port}`,
    requests,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

/** 收集寫入內容的假 stream。 */
export function memoryStream() {
  let data = "";
  return { write: (s) => { data += s; return true; }, get text() { return data; } };
}
