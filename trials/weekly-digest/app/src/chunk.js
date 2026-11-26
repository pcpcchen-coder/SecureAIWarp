// 把過長的文字切成多段，盡量在段落、換行、句號處斷開。

/**
 * 將 text 切成每段不超過 maxChars 個字元的片段。
 * 優先順序：空行（段落）> 換行 > 中英文句尾標點 > 硬切。
 */
export function splitText(text, maxChars) {
  if (!Number.isInteger(maxChars) || maxChars < 100) {
    throw new Error("maxChars 必須是 >= 100 的整數");
  }
  const chunks = [];
  let rest = text;
  while (rest.length > maxChars) {
    const window = rest.slice(0, maxChars);
    const minCut = Math.floor(maxChars * 0.5);
    let cut = -1;
    for (const re of [/\n\s*\n/g, /\n/g, /[。！？!?.;；]/g]) {
      let m;
      let last = -1;
      while ((m = re.exec(window)) !== null) last = m.index + m[0].length;
      if (last >= minCut) {
        cut = last;
        break;
      }
    }
    if (cut === -1) cut = maxChars;
    chunks.push(rest.slice(0, cut).trim());
    rest = rest.slice(cut);
  }
  if (rest.trim()) chunks.push(rest.trim());
  return chunks.filter(Boolean);
}

/**
 * 將多段文字依序分組，每組總長不超過 maxChars（單一項目超過時自成一組）。
 */
export function groupBySize(items, maxChars) {
  const groups = [];
  let current = [];
  let size = 0;
  for (const item of items) {
    if (current.length && size + item.length > maxChars) {
      groups.push(current);
      current = [];
      size = 0;
    }
    current.push(item);
    size += item.length;
  }
  if (current.length) groups.push(current);
  return groups;
}
