import fs from "node:fs/promises";
import path from "node:path";
import { parseArgs } from "node:util";
import Anthropic from "@anthropic-ai/sdk";
import { collectNotes, formatDate } from "./notes.js";
import { buildDigest, planNotes, DEFAULTS } from "./digest.js";
import { askClaude, createClient, DEFAULT_MODEL, ClaudeResponseError } from "./claude.js";

export const HELP = `用法：weekly-digest <會議記錄資料夾> [選項]

讀取資料夾內最近 N 天的 .txt / .md 會議記錄，用 Claude 整理成 Markdown 週報。

選項：
  -o, --output <檔案>      週報輸出路徑（預設：./weekly-digest-<今天日期>.md）
  -d, --days <天數>        往回看幾天，含今天（預設：7）
  -r, --recursive          一併讀取子資料夾
  -m, --model <模型>       使用的模型（預設：${DEFAULT_MODEL}）
      --effort <等級>      low | medium | high | xhigh | max（預設：medium）
      --max-tokens <數字>  每次回應的 token 上限（預設：16000）
      --chunk-chars <數字> 單次送出的原文字元上限，超過就分段（預設：${DEFAULTS.chunkChars}）
      --concurrency <數字> 同時進行的請求數（預設：${DEFAULTS.concurrency}）
      --no-fallbacks       不使用伺服器端拒答備援（beta 功能）
      --dry-run            只列出會處理的檔案與分段，不呼叫 API
  -h, --help               顯示說明

金鑰：請設定環境變數 ANTHROPIC_API_KEY。`;

function toInt(value, name, min = 1) {
  const n = Number(value);
  if (!Number.isInteger(n) || n < min) throw new Error(`--${name} 必須是 >= ${min} 的整數`);
  return n;
}

export function parseCli(argv) {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      output: { type: "string", short: "o" },
      days: { type: "string", short: "d", default: "7" },
      recursive: { type: "boolean", short: "r", default: false },
      model: { type: "string", short: "m", default: DEFAULT_MODEL },
      effort: { type: "string", default: "medium" },
      "max-tokens": { type: "string", default: "16000" },
      "chunk-chars": { type: "string", default: String(DEFAULTS.chunkChars) },
      concurrency: { type: "string", default: String(DEFAULTS.concurrency) },
      "no-fallbacks": { type: "boolean", default: false },
      "dry-run": { type: "boolean", default: false },
      help: { type: "boolean", short: "h", default: false },
    },
  });
  const efforts = ["low", "medium", "high", "xhigh", "max"];
  if (!efforts.includes(values.effort)) throw new Error(`--effort 必須是 ${efforts.join(" | ")}`);
  return {
    help: values.help,
    dir: positionals[0],
    output: values.output,
    days: toInt(values.days, "days"),
    recursive: values.recursive,
    model: values.model,
    effort: values.effort,
    maxTokens: toInt(values["max-tokens"], "max-tokens", 1024),
    chunkChars: toInt(values["chunk-chars"], "chunk-chars", 100),
    concurrency: toInt(values.concurrency, "concurrency"),
    fallbacks: !values["no-fallbacks"],
    dryRun: values["dry-run"],
  };
}

function describeError(err) {
  if (err instanceof Anthropic.AuthenticationError) return "API 金鑰無效或未設定（401）。請確認 ANTHROPIC_API_KEY。";
  if (err instanceof Anthropic.PermissionDeniedError) return `沒有權限使用此模型或功能（403）：${err.message}`;
  if (err instanceof Anthropic.NotFoundError) return `找不到模型或端點（404）：${err.message}`;
  if (err instanceof Anthropic.RateLimitError) return "超過速率限制（429），已重試仍失敗。請稍後再試或調低 --concurrency。";
  if (err instanceof Anthropic.BadRequestError) return `請求格式錯誤（400）：${err.message}`;
  if (err instanceof Anthropic.APIConnectionError) return `無法連線到 Anthropic API：${err.message}`;
  if (err instanceof Anthropic.APIError) return `API 錯誤 ${err.status ?? ""}：${err.message}`;
  if (err instanceof ClaudeResponseError) return err.message;
  return err?.message ?? String(err);
}

/**
 * CLI 進入點。回傳 exit code。
 * deps 讓測試可以注入假的 client、時間與輸出。
 */
export async function main(argv, deps = {}) {
  const { stdout = process.stdout, stderr = process.stderr, now = new Date(), env = process.env } = deps;
  let opts;
  try {
    opts = parseCli(argv);
  } catch (err) {
    stderr.write(`${err.message}\n\n${HELP}\n`);
    return 2;
  }
  if (opts.help) {
    stdout.write(`${HELP}\n`);
    return 0;
  }
  if (!opts.dir) {
    stderr.write(`請指定會議記錄資料夾。\n\n${HELP}\n`);
    return 2;
  }

  try {
    const { notes, start, end } = await collectNotes(opts.dir, { now, days: opts.days, recursive: opts.recursive });
    stderr.write(`在 ${formatDate(start)} ～ ${formatDate(end)} 找到 ${notes.length} 份會議記錄。\n`);
    if (notes.length === 0) {
      stderr.write("沒有可處理的記錄，未產生週報。\n");
      return 1;
    }

    if (opts.dryRun) {
      for (const n of planNotes(notes, { chunkChars: opts.chunkChars })) {
        stdout.write(`${formatDate(n.date)}  ${n.name}  (${n.content.length} 字元, ${n.chunks.length} 段, 日期來源: ${n.dateSource === "filename" ? "檔名" : "修改時間"})\n`);
      }
      return 0;
    }

    let client = deps.client;
    if (!client) {
      if (!env.ANTHROPIC_API_KEY && !env.ANTHROPIC_AUTH_TOKEN) {
        stderr.write("未設定 ANTHROPIC_API_KEY。請先 export ANTHROPIC_API_KEY=... 或使用 node --env-file=.env。\n");
        return 2;
      }
      client = createClient();
    }
    const ask = (req) =>
      askClaude(client, { ...req, model: opts.model, effort: opts.effort, maxTokens: opts.maxTokens, fallbacks: opts.fallbacks });

    const markdown = await buildDigest(notes, ask, {
      start,
      end,
      chunkChars: opts.chunkChars,
      concurrency: opts.concurrency,
      onProgress: (msg) => stderr.write(`${msg}\n`),
    });

    const output = opts.output ?? `weekly-digest-${formatDate(now)}.md`;
    await fs.mkdir(path.dirname(path.resolve(output)), { recursive: true });
    await fs.writeFile(output, markdown, "utf8");
    stderr.write(`週報已儲存：${output}\n`);
    return 0;
  } catch (err) {
    stderr.write(`錯誤：${describeError(err)}\n`);
    return 1;
  }
}
