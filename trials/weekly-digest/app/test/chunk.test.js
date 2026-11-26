import { test } from "node:test";
import assert from "node:assert/strict";
import { splitText, groupBySize } from "../src/chunk.js";

test("短文字不切段", () => {
  assert.deepEqual(splitText("短短的記錄", 100), ["短短的記錄"]);
});

test("長文字切成不超過上限的段落，且不遺失內容", () => {
  const para = "這是一段會議討論內容，包含很多細節。".repeat(10);
  const text = Array.from({ length: 30 }, (_, i) => `第${i}段：${para}`).join("\n\n");
  const chunks = splitText(text, 1000);
  assert.ok(chunks.length > 1);
  for (const c of chunks) assert.ok(c.length <= 1000, `chunk 長度 ${c.length}`);
  assert.equal(chunks.join("").replace(/\s/g, ""), text.replace(/\s/g, ""));
  // 優先在段落邊界切：每段都以「第N段」開頭
  for (const c of chunks) assert.match(c, /^第\d+段/);
});

test("沒有任何斷點時硬切", () => {
  const text = "a".repeat(2500);
  const chunks = splitText(text, 1000);
  assert.deepEqual(chunks.map((c) => c.length), [1000, 1000, 500]);
});

test("maxChars 太小時拋錯", () => {
  assert.throws(() => splitText("x", 10));
});

test("groupBySize 依大小分組", () => {
  const groups = groupBySize(["aaaa", "bbbb", "cccc", "dddddddddd"], 9);
  assert.deepEqual(groups, [["aaaa", "bbbb"], ["cccc"], ["dddddddddd"]]);
});
