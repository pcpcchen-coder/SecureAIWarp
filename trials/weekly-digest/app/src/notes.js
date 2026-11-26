// 掃描資料夾、判斷每份記錄的日期、篩出時間範圍內的檔案。
import fs from "node:fs/promises";
import path from "node:path";

export const NOTE_EXTENSIONS = new Set([".txt", ".md", ".markdown"]);

const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * 從檔名取出日期（例如 2026-11-24-產品會議.md、20261124_standup.txt）。
 * 找不到或日期不合法時回傳 null。回傳的是當地時間當天 00:00。
 */
export function dateFromFilename(filename) {
  const m = path.basename(filename).match(/(20\d{2})[-_.]?(\d{2})[-_.]?(\d{2})(?!\d)/);
  if (!m) return null;
  const [y, mo, d] = [Number(m[1]), Number(m[2]), Number(m[3])];
  const date = new Date(y, mo - 1, d);
  if (date.getFullYear() !== y || date.getMonth() !== mo - 1 || date.getDate() !== d) {
    return null;
  }
  return date;
}

export function startOfDay(date) {
  return new Date(date.getFullYear(), date.getMonth(), date.getDate());
}

/**
 * 計算時間範圍：從 (今天 - (days-1)) 的 00:00 到 now。
 * days=7 代表含今天在內的最近七天。
 */
export function dateWindow(now, days) {
  const start = new Date(startOfDay(now).getTime() - (days - 1) * DAY_MS);
  return { start, end: now };
}

async function listFiles(dir, recursive) {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  const out = [];
  for (const entry of entries) {
    if (entry.name.startsWith(".")) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (recursive) out.push(...(await listFiles(full, recursive)));
    } else if (entry.isFile() && NOTE_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) {
      out.push(full);
    }
  }
  return out;
}

/**
 * 找出時間範圍內的會議記錄。
 * 日期判斷：檔名有日期就用檔名日期，否則用檔案修改時間。
 * 回傳依日期排序的 [{ file, name, date, dateSource, content }]。
 */
export async function collectNotes(dir, { now = new Date(), days = 7, recursive = false } = {}) {
  const stat = await fs.stat(dir).catch(() => null);
  if (!stat || !stat.isDirectory()) {
    throw new Error(`找不到資料夾：${dir}`);
  }
  const { start, end } = dateWindow(now, days);
  const endOfToday = new Date(startOfDay(end).getTime() + DAY_MS - 1);

  const files = await listFiles(dir, recursive);
  const notes = [];
  for (const file of files) {
    let date = dateFromFilename(file);
    let dateSource = "filename";
    let inRange;
    if (date) {
      inRange = date >= start && date <= endOfToday;
    } else {
      date = (await fs.stat(file)).mtime;
      dateSource = "mtime";
      inRange = date >= start && date <= end;
    }
    if (!inRange) continue;
    const content = (await fs.readFile(file, "utf8")).replace(/^﻿/, "");
    if (!content.trim()) continue;
    notes.push({ file, name: path.relative(dir, file), date, dateSource, content });
  }
  notes.sort((a, b) => a.date - b.date || a.name.localeCompare(b.name));
  return { notes, start, end };
}

export function formatDate(date) {
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, "0");
  const d = String(date.getDate()).padStart(2, "0");
  return `${y}-${m}-${d}`;
}
