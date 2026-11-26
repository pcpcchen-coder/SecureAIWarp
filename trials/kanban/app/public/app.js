'use strict';

(function () {
  const { parseTags, isOverdue } = window.KanbanHelpers;
  const COLUMNS = ['todo', 'doing', 'done'];

  const els = {
    search: document.getElementById('search'),
    addBtn: document.getElementById('add-btn'),
    status: document.getElementById('status'),
    dialog: document.getElementById('card-dialog'),
    form: document.getElementById('card-form'),
    dialogTitle: document.getElementById('dialog-title'),
    formError: document.getElementById('form-error'),
    cancelBtn: document.getElementById('cancel-btn'),
    template: document.getElementById('card-template'),
  };

  let cards = [];
  let editingId = null;
  let draggingId = null;
  let searchTimer = null;

  async function api(method, url, body) {
    const opts = { method, headers: {} };
    if (body !== undefined) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(url, opts);
    if (res.status === 204) return null;
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    return data;
  }

  function showStatus(msg) {
    els.status.textContent = msg || '';
    els.status.hidden = !msg;
  }

  async function refresh() {
    try {
      const q = els.search.value.trim();
      const data = await api('GET', '/api/cards' + (q ? `?q=${encodeURIComponent(q)}` : ''));
      cards = data.cards;
      render();
      showStatus('');
    } catch (err) {
      showStatus('無法載入卡片：' + err.message);
    }
  }

  function renderCard(card) {
    const node = els.template.content.firstElementChild.cloneNode(true);
    node.dataset.id = card.id;
    node.querySelector('.card-title').textContent = card.title;
    node.querySelector('.card-desc').textContent = card.description || '';
    const tagList = node.querySelector('.tags');
    for (const tag of card.tags) {
      const li = document.createElement('li');
      li.textContent = tag;
      tagList.appendChild(li);
    }
    const due = node.querySelector('.due');
    if (card.dueDate) {
      const overdue = isOverdue(card);
      due.textContent = (overdue ? '已逾期 ' : '到期 ') + card.dueDate;
      due.classList.toggle('overdue', overdue);
    }
    node.querySelector('.edit').addEventListener('click', () => openDialog(card));
    node.querySelector('.delete').addEventListener('click', () => deleteCard(card));
    node.addEventListener('dblclick', () => openDialog(card));
    node.addEventListener('dragstart', (e) => {
      draggingId = card.id;
      node.classList.add('dragging');
      e.dataTransfer.effectAllowed = 'move';
      e.dataTransfer.setData('text/plain', card.id);
    });
    node.addEventListener('dragend', () => {
      draggingId = null;
      node.classList.remove('dragging');
      document.querySelectorAll('.cards.drag-over').forEach((el) => el.classList.remove('drag-over'));
    });
    return node;
  }

  function render() {
    const searching = els.search.value.trim() !== '';
    for (const col of COLUMNS) {
      const container = document.querySelector(`.cards[data-column="${col}"]`);
      const colCards = cards.filter((c) => c.column === col);
      container.replaceChildren(...colCards.map(renderCard));
      if (!colCards.length) {
        const p = document.createElement('p');
        p.className = 'empty';
        p.textContent = searching ? '沒有符合的卡片' : '拖曳卡片到這裡';
        container.appendChild(p);
      }
      document.querySelector(`[data-count="${col}"]`).textContent = colCards.length;
    }
  }

  // Card element directly below the pointer's vertical position, or null for "end of column".
  function cardAfterPointer(container, y) {
    const others = [...container.querySelectorAll('.card:not(.dragging)')];
    for (const el of others) {
      const box = el.getBoundingClientRect();
      if (y < box.top + box.height / 2) return el;
    }
    return null;
  }

  function setupDropZones() {
    document.querySelectorAll('.cards').forEach((container) => {
      container.addEventListener('dragover', (e) => {
        if (!draggingId) return;
        e.preventDefault();
        e.dataTransfer.dropEffect = 'move';
        container.classList.add('drag-over');
      });
      container.addEventListener('dragleave', (e) => {
        if (!container.contains(e.relatedTarget)) container.classList.remove('drag-over');
      });
      container.addEventListener('drop', async (e) => {
        e.preventDefault();
        container.classList.remove('drag-over');
        const id = draggingId || e.dataTransfer.getData('text/plain');
        if (!id) return;
        const before = cardAfterPointer(container, e.clientY);
        try {
          await api('POST', `/api/cards/${encodeURIComponent(id)}/move`, {
            column: container.dataset.column,
            beforeId: before ? before.dataset.id : null,
          });
        } catch (err) {
          showStatus('移動失敗：' + err.message);
        }
        refresh();
      });
    });
  }

  function openDialog(card) {
    editingId = card ? card.id : null;
    els.dialogTitle.textContent = card ? '編輯卡片' : '新增卡片';
    const f = els.form.elements;
    f.title.value = card ? card.title : '';
    f.description.value = card ? card.description : '';
    f.tags.value = card ? card.tags.join(', ') : '';
    f.dueDate.value = card && card.dueDate ? card.dueDate : '';
    f.column.value = card ? card.column : 'todo';
    els.formError.hidden = true;
    els.dialog.showModal();
    f.title.focus();
  }

  async function submitForm(e) {
    e.preventDefault();
    const f = els.form.elements;
    const payload = {
      title: f.title.value,
      description: f.description.value,
      tags: parseTags(f.tags.value),
      dueDate: f.dueDate.value || null,
      column: f.column.value,
    };
    try {
      if (editingId) await api('PATCH', `/api/cards/${encodeURIComponent(editingId)}`, payload);
      else await api('POST', '/api/cards', payload);
      els.dialog.close();
      refresh();
    } catch (err) {
      els.formError.textContent = err.message;
      els.formError.hidden = false;
    }
  }

  async function deleteCard(card) {
    if (!confirm(`確定要刪除「${card.title}」嗎？`)) return;
    try {
      await api('DELETE', `/api/cards/${encodeURIComponent(card.id)}`);
    } catch (err) {
      showStatus('刪除失敗：' + err.message);
    }
    refresh();
  }

  els.addBtn.addEventListener('click', () => openDialog(null));
  els.cancelBtn.addEventListener('click', () => els.dialog.close());
  els.form.addEventListener('submit', submitForm);
  els.search.addEventListener('input', () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(refresh, 150);
  });
  setupDropZones();
  refresh();
})();
