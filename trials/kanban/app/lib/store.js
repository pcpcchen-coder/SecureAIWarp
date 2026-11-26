'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const COLUMNS = ['todo', 'doing', 'done'];
const LIMITS = { title: 200, description: 5000, tag: 30, tags: 20 };

class ValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ValidationError';
    this.status = 400;
  }
}

class NotFoundError extends Error {
  constructor(message) {
    super(message);
    this.name = 'NotFoundError';
    this.status = 404;
  }
}

function isValidDate(str) {
  if (typeof str !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(str)) return false;
  const d = new Date(str + 'T00:00:00Z');
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === str;
}

function normalizeTitle(v) {
  if (typeof v !== 'string') throw new ValidationError('標題必須是文字');
  const t = v.trim();
  if (!t) throw new ValidationError('標題不可為空');
  if (t.length > LIMITS.title) throw new ValidationError(`標題最多 ${LIMITS.title} 字`);
  return t;
}

function normalizeDescription(v) {
  if (v === undefined || v === null) return '';
  if (typeof v !== 'string') throw new ValidationError('描述必須是文字');
  if (v.length > LIMITS.description) throw new ValidationError(`描述最多 ${LIMITS.description} 字`);
  return v;
}

function normalizeTags(v) {
  if (v === undefined || v === null) return [];
  if (!Array.isArray(v)) throw new ValidationError('標籤必須是陣列');
  const out = [];
  for (const raw of v) {
    if (typeof raw !== 'string') throw new ValidationError('標籤必須是文字');
    const t = raw.trim();
    if (!t) continue;
    if (t.length > LIMITS.tag) throw new ValidationError(`單一標籤最多 ${LIMITS.tag} 字`);
    if (!out.some((x) => x.toLowerCase() === t.toLowerCase())) out.push(t);
  }
  if (out.length > LIMITS.tags) throw new ValidationError(`標籤最多 ${LIMITS.tags} 個`);
  return out;
}

function normalizeDueDate(v) {
  if (v === undefined || v === null || v === '') return null;
  if (!isValidDate(v)) throw new ValidationError('到期日格式須為 YYYY-MM-DD');
  return v;
}

function normalizeColumn(v) {
  if (!COLUMNS.includes(v)) throw new ValidationError(`欄位必須是 ${COLUMNS.join(' / ')} 之一`);
  return v;
}

/**
 * JSON-file backed card store. All data is kept in memory and every
 * mutation is flushed to disk with an atomic write (temp file + rename),
 * so a crash mid-write never leaves a half-written data file.
 */
class Store {
  constructor(filePath) {
    this.filePath = path.resolve(filePath);
    this.cards = [];
    this._load();
  }

  _load() {
    let raw;
    try {
      raw = fs.readFileSync(this.filePath, 'utf8');
    } catch (err) {
      if (err.code === 'ENOENT') {
        this.cards = [];
        return;
      }
      throw err;
    }
    let data;
    try {
      data = JSON.parse(raw);
    } catch (err) {
      // Keep the unreadable file instead of silently overwriting the user's data.
      const backup = `${this.filePath}.corrupt-${Date.now()}`;
      fs.copyFileSync(this.filePath, backup);
      console.warn(`[kanban] 資料檔無法解析，已備份至 ${backup}，以空白看板啟動`);
      this.cards = [];
      return;
    }
    this.cards = Array.isArray(data.cards) ? data.cards.filter((c) => c && COLUMNS.includes(c.column)) : [];
  }

  _save() {
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    const tmp = `${this.filePath}.${process.pid}.tmp`;
    const payload = JSON.stringify({ version: 1, cards: this.cards }, null, 2);
    fs.writeFileSync(tmp, payload, 'utf8');
    fs.renameSync(tmp, this.filePath);
  }

  _get(id) {
    const card = this.cards.find((c) => c.id === id);
    if (!card) throw new NotFoundError('找不到這張卡片');
    return card;
  }

  _columnCards(column) {
    return this.cards.filter((c) => c.column === column).sort((a, b) => a.order - b.order);
  }

  _renumber(column) {
    this._columnCards(column).forEach((c, i) => {
      c.order = i;
    });
  }

  list(query) {
    const q = typeof query === 'string' ? query.trim().toLowerCase() : '';
    const sorted = COLUMNS.flatMap((col) => this._columnCards(col));
    if (!q) return sorted;
    const terms = q.split(/\s+/);
    return sorted.filter((c) => {
      const hay = [c.title, c.description, ...c.tags].join('\n').toLowerCase();
      return terms.every((t) => hay.includes(t));
    });
  }

  get(id) {
    return this._get(id);
  }

  create(input) {
    if (!input || typeof input !== 'object') throw new ValidationError('請提供卡片資料');
    const column = input.column === undefined ? 'todo' : normalizeColumn(input.column);
    const now = new Date().toISOString();
    const card = {
      id: crypto.randomUUID(),
      title: normalizeTitle(input.title),
      description: normalizeDescription(input.description),
      tags: normalizeTags(input.tags),
      dueDate: normalizeDueDate(input.dueDate),
      column,
      order: this._columnCards(column).length,
      createdAt: now,
      updatedAt: now,
    };
    this.cards.push(card);
    this._save();
    return card;
  }

  update(id, input) {
    if (!input || typeof input !== 'object') throw new ValidationError('請提供要更新的資料');
    const card = this._get(id);
    const next = {};
    if ('title' in input) next.title = normalizeTitle(input.title);
    if ('description' in input) next.description = normalizeDescription(input.description);
    if ('tags' in input) next.tags = normalizeTags(input.tags);
    if ('dueDate' in input) next.dueDate = normalizeDueDate(input.dueDate);
    let moveTo = null;
    if ('column' in input) moveTo = normalizeColumn(input.column);
    Object.assign(card, next);
    if (moveTo && moveTo !== card.column) {
      const from = card.column;
      card.column = moveTo;
      card.order = Number.MAX_SAFE_INTEGER;
      this._renumber(from);
      this._renumber(moveTo);
    }
    card.updatedAt = new Date().toISOString();
    this._save();
    return card;
  }

  /**
   * Move a card to `column`, placed directly before the card `beforeId`
   * (or at the end of the column when beforeId is null/undefined).
   */
  move(id, column, beforeId) {
    const card = this._get(id);
    const target = normalizeColumn(column);
    if (beforeId === id) return card;
    const from = card.column;
    const rest = this._columnCards(target).filter((c) => c.id !== id);
    let index = rest.length;
    if (beforeId !== undefined && beforeId !== null) {
      index = rest.findIndex((c) => c.id === beforeId);
      if (index === -1) throw new ValidationError('目標位置的卡片不在該欄位');
    }
    rest.splice(index, 0, card);
    card.column = target;
    rest.forEach((c, i) => {
      c.order = i;
    });
    if (from !== target) this._renumber(from);
    card.updatedAt = new Date().toISOString();
    this._save();
    return card;
  }

  remove(id) {
    const card = this._get(id);
    this.cards = this.cards.filter((c) => c.id !== id);
    this._renumber(card.column);
    this._save();
    return card;
  }
}

module.exports = { Store, ValidationError, NotFoundError, COLUMNS, isValidDate };
