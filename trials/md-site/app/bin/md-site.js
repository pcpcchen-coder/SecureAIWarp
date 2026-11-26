#!/usr/bin/env node
'use strict';

const { buildSite } = require('../src/build');

const USAGE = `用法: md-site <筆記資料夾> -o <輸出資料夾> [選項]

選項:
  -o, --out <dir>      輸出資料夾（必填）
  -t, --title <text>   網站標題（預設為輸入資料夾名稱）
      --clean          建置前先清空輸出資料夾
      --strict         有失效的筆記連結時以錯誤碼 2 結束
  -q, --quiet          不輸出訊息
  -h, --help           顯示說明
`;

function parseArgs(argv) {
  const opts = { clean: false, strict: false, quiet: false };
  const positional = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => {
      if (i + 1 >= argv.length) throw new Error(`${a} 需要一個值`);
      return argv[++i];
    };
    if (a === '-h' || a === '--help') opts.help = true;
    else if (a === '-o' || a === '--out') opts.output = next();
    else if (a.startsWith('--out=')) opts.output = a.slice(6);
    else if (a === '-t' || a === '--title') opts.title = next();
    else if (a.startsWith('--title=')) opts.title = a.slice(8);
    else if (a === '--clean') opts.clean = true;
    else if (a === '--strict') opts.strict = true;
    else if (a === '-q' || a === '--quiet') opts.quiet = true;
    else if (a.startsWith('-') && a !== '-') throw new Error(`未知選項: ${a}`);
    else positional.push(a);
  }
  opts.input = positional[0];
  if (positional.length > 1) throw new Error(`多餘的參數: ${positional.slice(1).join(' ')}`);
  return opts;
}

function main(argv) {
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (e) {
    process.stderr.write(`錯誤: ${e.message}\n\n${USAGE}`);
    return 1;
  }
  if (opts.help) { process.stdout.write(USAGE); return 0; }
  if (!opts.input || !opts.output) {
    process.stderr.write(`錯誤: 需要指定輸入資料夾與 -o 輸出資料夾\n\n${USAGE}`);
    return 1;
  }
  try {
    const result = buildSite({
      input: opts.input,
      output: opts.output,
      title: opts.title,
      clean: opts.clean,
      log: opts.quiet ? undefined : (m) => process.stderr.write(m + '\n'),
    });
    if (opts.strict && result.brokenLinks.length) return 2;
    return 0;
  } catch (e) {
    process.stderr.write(`錯誤: ${e.message}\n`);
    return 1;
  }
}

if (require.main === module) process.exitCode = main(process.argv.slice(2));

module.exports = { main, parseArgs };
