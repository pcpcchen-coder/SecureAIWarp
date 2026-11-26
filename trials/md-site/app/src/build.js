'use strict';

const fs = require('fs');
const path = require('path');
const { Marked } = require('marked');
const hljs = require('highlight.js');
const matter = require('gray-matter');

const MD_EXT = new Set(['.md', '.markdown']);
const SKIP_DIRS = new Set(['node_modules', '.git']);

/** Convert a path to POSIX separators. */
function toPosix(p) {
  return p.split(path.sep).join('/');
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Heading slug: keeps letters/digits of any script (e.g. CJK), spaces -> '-'. */
function slugify(text) {
  return String(text)
    .replace(/<[^>]*>/g, '')
    .replace(/&[a-z0-9#]+;/gi, '')
    .trim()
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\s_-]/gu, '')
    .replace(/\s+/g, '-');
}

/** Recursively list files under dir (relative POSIX paths), skipping hidden dirs and `exclude`. */
function walk(root, exclude) {
  const out = [];
  (function rec(dir) {
    const entries = fs.readdirSync(dir, { withFileTypes: true })
      .sort((a, b) => a.name.localeCompare(b.name));
    for (const e of entries) {
      const abs = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (e.name.startsWith('.') || SKIP_DIRS.has(e.name)) continue;
        if (exclude && path.resolve(abs) === exclude) continue;
        rec(abs);
      } else if (e.isFile()) {
        if (e.name.startsWith('.')) continue;
        out.push(toPosix(path.relative(root, abs)));
      }
    }
  })(root);
  return out;
}

function isMarkdown(rel) {
  return MD_EXT.has(path.posix.extname(rel).toLowerCase());
}

/** Map each source markdown path to an output html path; root index.md would clash with the home page. */
function outputPathFor(rel) {
  const base = rel.slice(0, -path.posix.extname(rel).length);
  if (base.toLowerCase() === 'index') return 'index-note.html';
  return base + '.html';
}

function isExternal(href) {
  return /^[a-z][a-z0-9+.-]*:/i.test(href) || href.startsWith('//');
}

function safeDecode(s) {
  try { return decodeURIComponent(s); } catch { return s; }
}

/** Encode each segment of a relative POSIX path for use in an href. */
function encodePath(p) {
  return p.split('/').map((seg) => (seg === '..' || seg === '.' ? seg : encodeURIComponent(seg))).join('/');
}

function relHref(fromOut, toOut) {
  const rel = path.posix.relative(path.posix.dirname(fromOut), toOut) || path.posix.basename(toOut);
  return encodePath(rel);
}

function extractTitle(content, data, rel) {
  if (data && typeof data.title === 'string' && data.title.trim()) return data.title.trim();
  const m = content.match(/^#\s+(.+?)\s*#*\s*$/m);
  if (m) return m[1].replace(/[*_`]/g, '').trim();
  return path.posix.basename(rel, path.posix.extname(rel));
}

/**
 * Build a static site.
 * @param {object} opts
 * @param {string} opts.input  source folder with markdown notes
 * @param {string} opts.output destination folder
 * @param {string} [opts.title] site title
 * @param {boolean} [opts.clean] empty output folder first
 * @param {(msg:string)=>void} [opts.log]
 * @returns {{pages:number, assets:number, brokenLinks:Array<{page:string, href:string}>}}
 */
function buildSite(opts) {
  const input = path.resolve(opts.input);
  const output = path.resolve(opts.output);
  const log = opts.log || (() => {});

  if (!fs.existsSync(input) || !fs.statSync(input).isDirectory()) {
    throw new Error(`Input folder not found: ${opts.input}`);
  }
  if (input === output) throw new Error('Output folder must differ from input folder');
  const inRel = path.relative(output, input);
  if (!inRel.startsWith('..') && !path.isAbsolute(inRel)) {
    throw new Error('Output folder must not contain the input folder');
  }
  const siteTitle = opts.title || path.basename(input);

  if (opts.clean && fs.existsSync(output)) fs.rmSync(output, { recursive: true, force: true });
  fs.mkdirSync(output, { recursive: true });

  const files = walk(input, output);
  const mdFiles = files.filter(isMarkdown);
  const otherFiles = files.filter((f) => !isMarkdown(f));

  // Lookup tables for link resolution.
  const outMap = new Map(); // src rel (lowercase) -> out rel
  const byName = new Map(); // basename w/o ext (lowercase) -> src rel (for [[wiki links]])
  for (const rel of mdFiles) {
    outMap.set(rel.toLowerCase(), outputPathFor(rel));
    const name = path.posix.basename(rel, path.posix.extname(rel)).toLowerCase();
    if (!byName.has(name)) byName.set(name, rel);
  }
  const fileSet = new Set(files.map((f) => f.toLowerCase()));

  const notes = mdFiles.map((rel) => {
    const raw = fs.readFileSync(path.join(input, rel), 'utf8');
    let parsed;
    try { parsed = matter(raw); } catch { parsed = { content: raw, data: {} }; }
    return { rel, out: outputPathFor(rel), content: parsed.content, data: parsed.data || {},
      title: extractTitle(parsed.content, parsed.data, rel) };
  });

  const brokenLinks = [];

  for (const note of notes) {
    const html = renderMarkdown(note, { outMap, byName, fileSet, brokenLinks, log });
    const page = layout({
      siteTitle,
      title: note.title,
      body: html,
      root: relHref(note.out, 'index.html').replace(/index\.html$/, ''),
      breadcrumb: note.rel,
    });
    const dest = path.join(output, note.out);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, page);
  }

  for (const rel of otherFiles) {
    const dest = path.join(output, rel);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.copyFileSync(path.join(input, rel), dest);
  }

  // Assets: stylesheet + highlight themes.
  const assetsDir = path.join(output, 'assets');
  fs.mkdirSync(assetsDir, { recursive: true });
  const stylesDir = path.join(path.dirname(require.resolve('highlight.js/package.json')), 'styles');
  fs.copyFileSync(path.join(stylesDir, 'github.min.css'), path.join(assetsDir, 'hljs-light.css'));
  fs.copyFileSync(path.join(stylesDir, 'github-dark.min.css'), path.join(assetsDir, 'hljs-dark.css'));
  fs.copyFileSync(path.join(__dirname, 'style.css'), path.join(assetsDir, 'style.css'));

  fs.writeFileSync(path.join(output, 'index.html'), layout({
    siteTitle,
    title: siteTitle,
    body: renderIndex(siteTitle, notes),
    root: '',
    breadcrumb: null,
  }));

  for (const b of brokenLinks) log(`warning: broken link in ${b.page}: ${b.href}`);
  log(`Built ${notes.length} page(s), copied ${otherFiles.length} file(s) -> ${output}`);
  return { pages: notes.length, assets: otherFiles.length, brokenLinks };
}

/** Resolve a local link target (relative to the note) and return the rewritten href or null. */
function resolveLocal(note, href, ctx) {
  const hashIdx = href.indexOf('#');
  const pathPart = hashIdx >= 0 ? href.slice(0, hashIdx) : href;
  let hash = hashIdx >= 0 ? href.slice(hashIdx) : '';
  const queryIdx = pathPart.indexOf('?');
  const cleanPath = safeDecode(queryIdx >= 0 ? pathPart.slice(0, queryIdx) : pathPart);
  if (!cleanPath) return { href, ok: true }; // pure #anchor
  if (hash) hash = '#' + encodeURIComponent(safeDecode(hash.slice(1)));

  const target = cleanPath.startsWith('/')
    ? path.posix.normalize(cleanPath.slice(1))
    : path.posix.normalize(path.posix.join(path.posix.dirname(note.rel), cleanPath));
  const key = target.toLowerCase();

  if (isMarkdown(target)) {
    const out = ctx.outMap.get(key);
    if (out) return { href: relHref(note.out, out) + hash, ok: true };
    return { href: encodePath(cleanPath) + hash, ok: false };
  }
  // Extension-less link that matches a note, e.g. [x](other-note)
  if (!path.posix.extname(target)) {
    for (const ext of MD_EXT) {
      const out = ctx.outMap.get(key + ext);
      if (out) return { href: relHref(note.out, out) + hash, ok: true };
    }
  }
  const exists = ctx.fileSet.has(key) || ctx.fileSet.has(key.replace(/\/$/, ''));
  return { href: encodePath(cleanPath) + hash, ok: exists || cleanPath.endsWith('/') };
}

function renderMarkdown(note, ctx) {
  const slugCounts = new Map();
  const marked = new Marked({ gfm: true });

  marked.use({
    renderer: {
      code(code, infostring) {
        const lang = (infostring || '').trim().split(/\s+/)[0].toLowerCase();
        let html;
        let cls = 'hljs';
        if (lang && hljs.getLanguage(lang)) {
          html = hljs.highlight(code, { language: lang, ignoreIllegals: true }).value;
          cls += ` language-${escapeHtml(lang)}`;
        } else {
          html = escapeHtml(code);
        }
        return `<pre><code class="${cls}">${html}</code></pre>\n`;
      },
      heading(text, level, raw) {
        let slug = slugify(raw) || 'section';
        const n = slugCounts.get(slug) || 0;
        slugCounts.set(slug, n + 1);
        if (n) slug = `${slug}-${n}`;
        return `<h${level} id="${escapeHtml(slug)}"><a class="anchor" href="#${encodeURIComponent(slug)}" aria-hidden="true">#</a>${text}</h${level}>\n`;
      },
      link(href, title, text) {
        if (!href) return text;
        let cls = '';
        if (!isExternal(href)) {
          const r = resolveLocal(note, href, ctx);
          if (!r.ok) {
            ctx.brokenLinks.push({ page: note.rel, href });
            cls = ' class="broken-link"';
          }
          href = r.href;
        }
        const t = title ? ` title="${escapeHtml(title)}"` : '';
        return `<a href="${escapeHtml(href)}"${t}${cls}>${text}</a>`;
      },
      image(href, title, text) {
        if (!href) return escapeHtml(text);
        if (!isExternal(href)) href = resolveLocal(note, href, ctx).href;
        const t = title ? ` title="${escapeHtml(title)}"` : '';
        return `<img src="${escapeHtml(href)}" alt="${escapeHtml(text)}"${t} loading="lazy">`;
      },
    },
  });

  // [[Wiki Link]] / [[Wiki Link|label]] / [[Wiki Link#heading]] support (outside code).
  const src = replaceOutsideCode(note.content, (chunk) =>
    chunk.replace(/(!?)\[\[([^\]|#\n]+)(#[^\]|\n]*)?(?:\|([^\]\n]+))?\]\]/g, (m, bang, name, hash, label) => {
      if (bang) return m;
      const key = name.trim().toLowerCase();
      const relHit = byNameLookup(ctx, key);
      const text = (label || name).trim();
      const anchor = hash ? '#' + slugify(hash.slice(1)) : '';
      if (!relHit) {
        ctx.brokenLinks.push({ page: note.rel, href: `[[${name}]]` });
        return `<a class="broken-link" href="#">${escapeHtml(text)}</a>`;
      }
      const out = ctx.outMap.get(relHit.toLowerCase());
      return `<a href="${escapeHtml(relHref(note.out, out) + anchor)}">${escapeHtml(text)}</a>`;
    }));

  return marked.parse(src);
}

function byNameLookup(ctx, key) {
  const k = key.replace(/\.(md|markdown)$/i, '');
  if (ctx.outMap.has(k + '.md')) return k + '.md';
  return ctx.byName.get(path.posix.basename(k)) || null;
}

/** Apply fn only to text outside fenced code blocks and inline code spans. */
function replaceOutsideCode(text, fn) {
  const parts = text.split(/(^ {0,3}(?:```|~~~)[\s\S]*?^ {0,3}(?:```|~~~)[^\n]*$|`[^`\n]+`)/m);
  return parts.map((p, i) => (i % 2 === 1 ? p : fn(p))).join('');
}

function renderIndex(siteTitle, notes) {
  // Build a folder tree.
  const tree = { dirs: new Map(), notes: [] };
  for (const n of notes) {
    const segs = n.rel.split('/');
    segs.pop();
    let node = tree;
    for (const s of segs) {
      if (!node.dirs.has(s)) node.dirs.set(s, { dirs: new Map(), notes: [] });
      node = node.dirs.get(s);
    }
    node.notes.push(n);
  }
  const renderNode = (node) => {
    const items = [];
    const sorted = [...node.notes].sort((a, b) => a.title.localeCompare(b.title));
    for (const n of sorted) {
      items.push(`<li class="note"><a href="${escapeHtml(encodePath(n.out))}">${escapeHtml(n.title)}</a></li>`);
    }
    for (const [name, child] of [...node.dirs.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
      items.push(`<li class="folder"><details open><summary>${escapeHtml(name)}</summary>${renderNode(child)}</details></li>`);
    }
    return `<ul>${items.join('')}</ul>`;
  };
  return `<h1>${escapeHtml(siteTitle)}</h1>
<p class="meta">${notes.length} 篇筆記</p>
<input type="search" id="filter" placeholder="篩選筆記…" aria-label="篩選筆記">
<nav class="toc">${notes.length ? renderNode(tree) : '<p>（沒有找到任何 Markdown 檔案）</p>'}</nav>
<script>
(function(){var f=document.getElementById('filter');if(!f)return;f.addEventListener('input',function(){
var q=f.value.trim().toLowerCase();document.querySelectorAll('.toc li.note').forEach(function(li){
li.style.display=!q||li.textContent.toLowerCase().indexOf(q)>=0?'':'none';});});})();
</script>`;
}

function layout({ siteTitle, title, body, root, breadcrumb }) {
  const crumb = breadcrumb
    ? `<a href="${root}index.html">← ${escapeHtml(siteTitle)}</a> <span class="path">${escapeHtml(breadcrumb)}</span>`
    : '';
  return `<!doctype html>
<html lang="zh-Hant">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title === siteTitle ? title : `${title} · ${siteTitle}`)}</title>
<link rel="stylesheet" href="${root}assets/style.css">
<link rel="stylesheet" href="${root}assets/hljs-light.css" media="(prefers-color-scheme: light)">
<link rel="stylesheet" href="${root}assets/hljs-dark.css" media="(prefers-color-scheme: dark)">
</head>
<body>
<header class="site-header">${crumb || `<span>${escapeHtml(siteTitle)}</span>`}</header>
<main class="content">
${body}
</main>
</body>
</html>
`;
}

module.exports = { buildSite, slugify, outputPathFor, escapeHtml };
