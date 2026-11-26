// Pure helpers shared by the browser UI and the Node tests.
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.KanbanHelpers = api;
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  /** "工作, 緊急 ,,工作" -> ["工作", "緊急"] */
  function parseTags(text) {
    const out = [];
    for (const part of String(text || '').split(/[,，]/)) {
      const t = part.trim();
      if (t && !out.some((x) => x.toLowerCase() === t.toLowerCase())) out.push(t);
    }
    return out;
  }

  /** Local calendar date as YYYY-MM-DD. */
  function localDateString(date) {
    const d = date || new Date();
    const pad = (n) => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
  }

  /** A card is overdue when it has a due date before today and is not done. */
  function isOverdue(card, today) {
    if (!card || !card.dueDate || card.column === 'done') return false;
    return card.dueDate < (today || localDateString());
  }

  return { parseTags, localDateString, isOverdue };
});
