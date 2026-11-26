'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { parseTags, localDateString, isOverdue } = require('../public/helpers');

test('parseTags：支援半形與全形逗號、去空白、去重複', () => {
  assert.deepEqual(parseTags('工作, 緊急 ，,工作, Work, work'), ['工作', '緊急', 'Work']);
  assert.deepEqual(parseTags(''), []);
  assert.deepEqual(parseTags(undefined), []);
});

test('localDateString：輸出 YYYY-MM-DD', () => {
  assert.equal(localDateString(new Date(2026, 0, 5)), '2026-01-05');
});

test('isOverdue：今天以前且未完成才算逾期', () => {
  const today = '2026-11-26';
  assert.equal(isOverdue({ dueDate: '2026-11-25', column: 'todo' }, today), true);
  assert.equal(isOverdue({ dueDate: '2026-11-26', column: 'todo' }, today), false);
  assert.equal(isOverdue({ dueDate: '2026-11-25', column: 'done' }, today), false);
  assert.equal(isOverdue({ dueDate: null, column: 'todo' }, today), false);
});
