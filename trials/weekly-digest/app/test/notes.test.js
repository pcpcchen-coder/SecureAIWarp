import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { collectNotes, dateFromFilename, dateWindow, formatDate } from "../src/notes.js";
import { makeTempDir, writeNote } from "./helpers.js";

const NOW = new Date(2026, 10, 26, 15, 0, 0); // 2026-11-26 15:00 當地時間

test("dateFromFilename 解析多種日期格式", () => {
  assert.equal(formatDate(dateFromFilename("2026-11-24-產品會議.md")), "2026-11-24");
  assert.equal(formatDate(dateFromFilename("standup_20261120.txt")), "2026-11-20");
  assert.equal(formatDate(dateFromFilename("notes.2026.11.03.md")), "2026-11-03");
  assert.equal(dateFromFilename("會議.md"), null);
  assert.equal(dateFromFilename("2026-02-30.md"), null, "不合法的日期");
});

test("dateWindow 含今天往回 7 天", () => {
  const { start, end } = dateWindow(NOW, 7);
  assert.equal(formatDate(start), "2026-11-20");
  assert.equal(end, NOW);
});

test("collectNotes 依檔名日期或修改時間篩選、排序，並略過非記錄檔", async () => {
  const dir = await makeTempDir();
  try {
    await writeNote(dir, "2026-11-20-週會.md", "# 週會\n內容");
    await writeNote(dir, "2026-11-19-舊會議.md", "太舊");
    await writeNote(dir, "2026-11-26-今天.txt", "今天");
    await writeNote(dir, "沒日期-最近.txt", "最近修改", new Date(2026, 10, 25, 9));
    await writeNote(dir, "沒日期-很舊.txt", "很久以前", new Date(2026, 9, 1));
    await writeNote(dir, "2026-11-22-空白.md", "   \n");
    await writeNote(dir, "2026-11-23-圖片.png", "not a note");
    await writeNote(dir, "sub/2026-11-24-子資料夾.md", "子資料夾");

    const { notes } = await collectNotes(dir, { now: NOW, days: 7 });
    assert.deepEqual(
      notes.map((n) => n.name),
      ["2026-11-20-週會.md", "沒日期-最近.txt", "2026-11-26-今天.txt"],
    );
    assert.equal(notes[1].dateSource, "mtime");

    const rec = await collectNotes(dir, { now: NOW, days: 7, recursive: true });
    assert.ok(rec.notes.some((n) => n.name.endsWith("2026-11-24-子資料夾.md")));
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("collectNotes 資料夾不存在時拋出錯誤", async () => {
  await assert.rejects(collectNotes("/nonexistent/weekly-digest-dir"), /找不到資料夾/);
});
