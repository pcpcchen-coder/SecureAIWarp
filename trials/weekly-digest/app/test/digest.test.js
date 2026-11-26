import { test } from "node:test";
import assert from "node:assert/strict";
import { buildDigest, summarizeMeeting, summarizeWeek, mapLimit } from "../src/digest.js";

function fakeAsk() {
  const calls = [];
  const ask = async (req) => {
    calls.push(req);
    if (req.system.includes("其中一段")) return `段落筆記${calls.length}`;
    if (req.system.includes("濃縮")) return `濃縮${calls.length}`;
    if (req.system.includes("本週總結")) return "本週總結內容";
    return "#### 重點\n- 摘要內容";
  };
  return { ask, calls };
}

const note = (name, content, day) => ({ name, content, date: new Date(2026, 10, day), dateSource: "filename" });

test("短記錄只呼叫一次，記錄內容包在標籤裡", async () => {
  const { ask, calls } = fakeAsk();
  const out = await summarizeMeeting(note("a.md", "決議：採用方案A", 24), ask, { chunkChars: 1000 });
  assert.equal(calls.length, 1);
  assert.match(calls[0].prompt, /<meeting_notes>\n決議：採用方案A\n<\/meeting_notes>/);
  assert.match(calls[0].system, /待辦事項/);
  assert.match(calls[0].system, /負責人/);
  assert.equal(out, "#### 重點\n- 摘要內容");
});

test("長記錄先分段整理再合併，每次請求都不超過上限", async () => {
  const { ask, calls } = fakeAsk();
  const long = Array.from({ length: 20 }, (_, i) => `議題${i}：${"討論細節。".repeat(40)}`).join("\n\n");
  await summarizeMeeting(note("long.md", long, 24), ask, { chunkChars: 500 });
  const partCalls = calls.filter((c) => c.system.includes("其中一段"));
  assert.ok(partCalls.length > 1);
  assert.equal(calls.length, partCalls.length + 1, "分段數 + 1 次合併");
  for (const c of partCalls) {
    const body = c.prompt.split("<meeting_notes_part>\n")[1].split("\n</meeting_notes_part>")[0];
    assert.ok(body.length <= 500);
  }
  assert.match(calls.at(-1).prompt, /【第 1 段筆記】/);
});

test("摘要總量超過預算時先分批濃縮，再寫本週總結", async () => {
  const { ask, calls } = fakeAsk();
  const sections = Array.from({ length: 10 }, (_, i) => ({ title: `會議${i}`, date: "2026-11-24", summary: "x".repeat(300) }));
  const weekly = await summarizeWeek(sections, ask, { summaryBudgetChars: 1000, concurrency: 2 });
  assert.equal(weekly, "本週總結內容");
  const condense = calls.filter((c) => c.system.includes("濃縮"));
  assert.ok(condense.length >= 2);
  for (const c of condense) assert.ok(c.prompt.length <= 1000 + 100);
  assert.ok(calls.at(-1).system.includes("本週總結"));
});

test("摘要總量小時直接寫總結，不濃縮", async () => {
  const { ask, calls } = fakeAsk();
  await summarizeWeek([{ title: "A", date: "2026-11-24", summary: "short" }], ask, {});
  assert.equal(calls.length, 1);
});

test("buildDigest 產生完整週報結構，會議依序排列", async () => {
  const { ask } = fakeAsk();
  const notes = [note("2026-11-23-規劃.md", "# 產品規劃會議\n內容", 23), note("2026-11-25-standup.txt", "站會內容", 25)];
  const md = await buildDigest(notes, ask, { start: new Date(2026, 10, 20), end: new Date(2026, 10, 26), concurrency: 2 });
  assert.match(md, /^# 會議週報（2026-11-20 ～ 2026-11-26）/);
  assert.match(md, /共 2 場會議/);
  const a = md.indexOf("### 產品規劃會議（2026-11-23）");
  const b = md.indexOf("### 2026-11-25-standup（2026-11-25）");
  assert.ok(a > 0 && b > a);
  assert.match(md, /## 本週總結\n\n本週總結內容/);
  assert.match(md, /來源檔案：`2026-11-23-規劃.md`/);
});

test("mapLimit 限制並行數並保持順序", async () => {
  let active = 0;
  let peak = 0;
  const res = await mapLimit([5, 1, 3, 2, 4], 2, async (x) => {
    active++;
    peak = Math.max(peak, active);
    await new Promise((r) => setTimeout(r, x * 3));
    active--;
    return x * 10;
  });
  assert.deepEqual(res, [50, 10, 30, 20, 40]);
  assert.equal(peak, 2);
});
