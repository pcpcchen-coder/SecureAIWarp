#!/usr/bin/env bash
# thumbs.sh - 幫資料夾裡的圖片與影片產生縮圖，並拼成一張總覽圖。
#
# 用法: thumbs.sh [-w 寬度] [-c 欄數] [-o 總覽檔名] [-f] [-q] 輸入資料夾 輸出資料夾
# 需要: ffmpeg、ffprobe、ImageMagick (convert、montage)

set -u
set -o pipefail

PROG=$(basename "$0")
WIDTH=320
COLUMNS=5
OVERVIEW_NAME="overview.jpg"
FORCE=0
QUIET=0

IMAGE_EXTS="jpg jpeg png gif bmp webp tif tiff"
VIDEO_EXTS="mp4 mov mkv avi webm m4v mpg mpeg wmv flv 3gp"

usage() {
  cat <<EOF
用法: $PROG [選項] 輸入資料夾 輸出資料夾

  -w 寬度    縮圖寬度（像素，預設 $WIDTH；比原圖大時不放大）
  -c 欄數    總覽圖每列幾張（預設 $COLUMNS）
  -o 檔名    總覽圖檔名（預設 $OVERVIEW_NAME，存在輸出資料夾內）
  -f         強制重做所有縮圖
  -q         安靜模式，只印錯誤
  -h         顯示這段說明

圖片副檔名: $IMAGE_EXTS
影片副檔名: $VIDEO_EXTS
EOF
}

log() { [ "$QUIET" -eq 1 ] || printf '%s\n' "$*"; }
err() { printf '%s: %s\n' "$PROG" "$*" >&2; }

is_positive_int() { [[ $1 =~ ^[1-9][0-9]*$ ]]; }

while getopts ":w:c:o:fqh" opt; do
  case $opt in
    w) WIDTH=$OPTARG ;;
    c) COLUMNS=$OPTARG ;;
    o) OVERVIEW_NAME=$OPTARG ;;
    f) FORCE=1 ;;
    q) QUIET=1 ;;
    h) usage; exit 0 ;;
    :) err "選項 -$OPTARG 需要參數"; usage >&2; exit 2 ;;
    \?) err "未知選項 -$OPTARG"; usage >&2; exit 2 ;;
  esac
done
shift $((OPTIND - 1))

if [ $# -ne 2 ]; then
  usage >&2
  exit 2
fi
is_positive_int "$WIDTH" || { err "寬度必須是正整數: $WIDTH"; exit 2; }
is_positive_int "$COLUMNS" || { err "欄數必須是正整數: $COLUMNS"; exit 2; }
case $OVERVIEW_NAME in
  */*|"") err "總覽檔名不能包含路徑: $OVERVIEW_NAME"; exit 2 ;;
esac

IN_DIR=$1
OUT_DIR=$2

for tool in ffmpeg ffprobe convert montage; do
  command -v "$tool" >/dev/null 2>&1 || { err "找不到必要工具: $tool"; exit 3; }
done

[ -d "$IN_DIR" ] || { err "輸入資料夾不存在: $IN_DIR"; exit 2; }
mkdir -p "$OUT_DIR" || { err "無法建立輸出資料夾: $OUT_DIR"; exit 2; }

IN_ABS=$(cd "$IN_DIR" && pwd)
OUT_ABS=$(cd "$OUT_DIR" && pwd)

has_ext() { # has_ext 副檔名 清單
  local e
  for e in $2; do [ "$1" = "$e" ] && return 0; done
  return 1
}

# 產生圖片縮圖：多張（gif、tif）只取第一張；不放大小圖。
make_image_thumb() {
  convert "${1}[0]" -auto-orient -thumbnail "${WIDTH}x>" \
    -background white -alpha remove -alpha off -quality 85 "jpg:$2" 2>/dev/null
}

# 產生影片縮圖：擷取影片長度一半處的那一格。
make_video_thumb() {
  local src=$1 dst=$2 dur mid
  dur=$(ffprobe -v error -show_entries format=duration \
        -of default=noprint_wrappers=1:nokey=1 -- "$src" 2>/dev/null | head -n1)
  if [[ $dur =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    mid=$(awk -v d="$dur" 'BEGIN { printf "%.3f", d / 2 }')
  else
    mid=0
  fi
  local vf="scale='min(${WIDTH},iw)':-2"
  ffmpeg -nostdin -hide_banner -loglevel error -y -ss "$mid" -i "$src" \
    -frames:v 1 -vf "$vf" -f image2 -c:v mjpeg -q:v 3 "$dst" && [ -s "$dst" ] && return 0
  # 備援：某些檔案在中間點取不到畫面，改取第一格。
  ffmpeg -nostdin -hide_banner -loglevel error -y -i "$src" \
    -frames:v 1 -vf "$vf" -f image2 -c:v mjpeg -q:v 3 "$dst" && [ -s "$dst" ]
}

made=0 skipped=0 failed=0
thumbs=()

shopt -s nullglob
for src in "$IN_ABS"/*; do
  [ -f "$src" ] || continue
  name=$(basename "$src")
  [[ $name == .* ]] && continue
  [[ $name == *.* ]] || continue
  ext=${name##*.}
  ext=${ext,,}

  if has_ext "$ext" "$IMAGE_EXTS"; then
    kind=image
  elif has_ext "$ext" "$VIDEO_EXTS"; then
    kind=video
  else
    continue
  fi

  # 保留原副檔名，避免 a.jpg 和 a.png 撞名。
  dst="$OUT_ABS/$name.jpg"
  if [ "$dst" = "$OUT_ABS/$OVERVIEW_NAME" ]; then
    err "略過 $name：縮圖檔名與總覽圖相同"
    failed=$((failed + 1))
    continue
  fi

  if [ "$FORCE" -eq 0 ] && [ -s "$dst" ] && ! [ "$src" -nt "$dst" ]; then
    log "略過（已存在）: $name"
    skipped=$((skipped + 1))
    thumbs+=("$dst")
    continue
  fi

  tmp="$OUT_ABS/.tmp.$$.$RANDOM.jpg"
  if [ "$kind" = image ]; then
    make_image_thumb "$src" "$tmp"
  else
    make_video_thumb "$src" "$tmp"
  fi
  rc=$?
  if [ $rc -eq 0 ] && [ -s "$tmp" ] && mv -f "$tmp" "$dst"; then
    log "產生（$kind）: $name -> $(basename "$dst")"
    made=$((made + 1))
    thumbs+=("$dst")
  else
    rm -f "$tmp"
    err "失敗: $name"
    failed=$((failed + 1))
  fi
done

overview="$OUT_ABS/$OVERVIEW_NAME"
if [ ${#thumbs[@]} -eq 0 ]; then
  log "沒有可處理的圖片或影片，未產生總覽圖。"
else
  # 有新縮圖、總覽圖不存在、或縮圖集合改變時才重做總覽圖。
  list_file="$OUT_ABS/.overview.list"
  new_list=$(printf '%s\n' "${thumbs[@]}")
  need=0
  if [ "$made" -gt 0 ] || [ "$FORCE" -eq 1 ] || ! [ -s "$overview" ]; then
    need=1
  elif ! [ -f "$list_file" ] || [ "$(cat "$list_file")" != "$new_list" ]; then
    need=1
  fi

  if [ "$need" -eq 1 ]; then
    tmp="$OUT_ABS/.tmp.$$.overview.jpg"
    # 標籤用原始檔名（去掉最後加上的 .jpg）。
    args=()
    for t in "${thumbs[@]}"; do
      label=$(basename "$t" .jpg)
      args+=(-label "${label//%/%%}" "$t")
    done
    if montage "${args[@]}" -tile "${COLUMNS}x" \
         -geometry "${WIDTH}x${WIDTH}>+4+4" -background '#eeeeee' \
         -pointsize 12 -quality 85 "jpg:$tmp" 2>/dev/null && mv -f "$tmp" "$overview"; then
      printf '%s\n' "$new_list" > "$list_file"
      log "產生總覽圖: $overview（${#thumbs[@]} 張）"
    else
      rm -f "$tmp"
      err "總覽圖產生失敗"
      failed=$((failed + 1))
    fi
  else
    log "總覽圖已是最新: $overview"
  fi
fi

log "完成：新產生 $made、略過 $skipped、失敗 $failed"
[ "$failed" -eq 0 ]
