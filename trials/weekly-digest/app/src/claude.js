// 與 Claude API 溝通的薄封裝。所有請求都走 Messages API（POST /v1/messages）並使用串流，
// 避免長輸入／長輸出時的 HTTP 逾時。
import Anthropic from "@anthropic-ai/sdk";

export const DEFAULT_MODEL = "claude-opus-5-5";
export const FALLBACK_BETA = "server-side-fallback-2026-07-01";

/**
 * 建立 SDK client。金鑰由 SDK 從環境變數 ANTHROPIC_API_KEY 讀取
 * （也支援 ANTHROPIC_AUTH_TOKEN 與 `ant auth login` 的設定檔）。
 * baseURL 一般不需設定；SDK 預設連到 https://api.anthropic.com，
 * 也會讀 ANTHROPIC_BASE_URL。
 */
export function createClient({ baseURL, apiKey, maxRetries = 4 } = {}) {
  const opts = { maxRetries };
  if (baseURL) opts.baseURL = baseURL;
  if (apiKey) opts.apiKey = apiKey;
  return new Anthropic(opts);
}

export class ClaudeResponseError extends Error {}

/**
 * 呼叫一次 Claude，回傳文字結果。
 * @param {Anthropic} client
 * @param {{system: string, prompt: string, model?: string, effort?: string,
 *          maxTokens?: number, fallbacks?: boolean}} req
 */
export async function askClaude(client, { system, prompt, model = DEFAULT_MODEL, effort = "medium", maxTokens = 16000, fallbacks = true }) {
  const params = {
    model,
    max_tokens: maxTokens,
    system,
    output_config: { effort },
    messages: [{ role: "user", content: prompt }],
  };

  let message;
  if (fallbacks) {
    // 伺服器端備援：若安全分類器拒答，API 會在同一個請求內自動改用合適的模型完成。
    const stream = client.beta.messages.stream({
      ...params,
      betas: [FALLBACK_BETA],
      fallbacks: "default",
    });
    message = await stream.finalMessage();
  } else {
    const stream = client.messages.stream(params);
    message = await stream.finalMessage();
  }

  if (message.stop_reason === "refusal") {
    const cat = message.stop_details?.category ?? "unknown";
    throw new ClaudeResponseError(`Claude 拒絕處理此內容（category: ${cat}）`);
  }
  const text = message.content
    .filter((b) => b.type === "text")
    .map((b) => b.text)
    .join("")
    .trim();
  if (message.stop_reason === "max_tokens") {
    throw new ClaudeResponseError(
      `回應超過 max_tokens（${maxTokens}）被截斷；請用 --max-tokens 調高或用 --chunk-chars 調小分段`,
    );
  }
  if (!text) {
    throw new ClaudeResponseError(`Claude 回傳空白內容（stop_reason: ${message.stop_reason}）`);
  }
  return text;
}
