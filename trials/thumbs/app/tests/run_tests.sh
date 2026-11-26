#!/usr/bin/env bash
# 自動化測試：現場用 ffmpeg / ImageMagick 產生測試素材，再驗證 thumbs.sh 的行為。
# 用法: tests/run_tests.sh

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPT="$HERE/../thumbs.sh"
# 暫存資料放在 tests/ 底下（可用 THUMBS_TEST_TMP 改位置），結束時自動刪除。
WORK=$(mktemp -d "${THUMBS_TEST_TMP:-$HERE}/.work.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

pass=0 fail=0 failed_names=()

ok()   { pass=$((pass + 1)); printf 'ok   - %s\n' "$1"; }
nok()  { fail=$((fail + 1)); failed_names+=("$1"); printf 'FAIL - %s\n' "$1"; [ -n "${2:-}" ] && printf '       %s\n' "$2"; }

width_of()  { identify -format '%w' "$1[0]" 2>/dev/null; }
height_of() { identify -format '%h' "$1[0]" 2>/dev/null; }
# 回傳某點的主色：red / green / blue / other
color_at() {
  local rgb r g b
  rgb=$(convert "$1" -format '%[fx:int(255*p{'"$2"','"$3"'}.r)] %[fx:int(255*p{'"$2"','"$3"'}.g)] %[fx:int(255*p{'"$2"','"$3"'}.b)]' info: 2>/dev/null)
  read -r r g b <<<"$rgb"
  if   [ "$r" -gt 180 ] && [ "$g" -lt 80 ] && [ "$b" -lt 80 ]; then echo red
  elif [ "$g" -gt 100 ] && [ "$r" -lt 80 ] && [ "$b" -lt 80 ]; then echo green
  elif [ "$b" -gt 180 ] && [ "$r" -lt 80 ] && [ "$g" -lt 80 ]; then echo blue
  else echo "other($r,$g,$b)"; fi
}
mtime() { stat -c %Y.%N "$1" 2>/dev/null || stat -f %m "$1"; }

# ---- 產生素材 ----
make_video_rgb() { # 3 秒影片：0-1 紅、1-2 綠、2-3 藍 → 中間一格應為綠
  ffmpeg -nostdin -hide_banner -loglevel error -y \
    -f lavfi -i "color=c=red:s=320x240:d=1:r=10" \
    -f lavfi -i "color=c=0x00ff00:s=320x240:d=1:r=10" \
    -f lavfi -i "color=c=blue:s=320x240:d=1:r=10" \
    -filter_complex "[0][1][2]concat=n=3:v=1:a=0,format=yuv420p" "$1"
}
make_fixtures() { # make_fixtures 目錄
  mkdir -p "$1"
  convert -size 800x600 xc:red "$1/photo.jpg"
  convert -size 1000x500 gradient:blue-yellow "$1/wide.png"
  make_video_rgb "$1/clip.mp4"
  echo "not media" > "$1/notes.txt"
}

run() { # run 輸出檔 其他參數...  （記錄 stdout+stderr 與結束碼到 RC）
  local out=$1; shift
  "$SCRIPT" "$@" >"$out" 2>&1
  RC=$?
}

# ---- 測試 ----
t_usage() {
  run "$WORK/u.log"
  [ "$RC" -eq 2 ] && grep -q '用法' "$WORK/u.log" && ok "沒給參數時顯示用法並回傳 2" || nok "沒給參數時顯示用法並回傳 2" "rc=$RC"
}

t_bad_input() {
  run "$WORK/b.log" "$WORK/no-such-dir" "$WORK/b-out"
  [ "$RC" -ne 0 ] && grep -q '不存在' "$WORK/b.log" && ok "輸入資料夾不存在時報錯" || nok "輸入資料夾不存在時報錯" "rc=$RC"
}

t_bad_width() {
  run "$WORK/w.log" -w abc "$WORK" "$WORK/w-out"
  [ "$RC" -eq 2 ] && ok "寬度不是正整數時報錯" || nok "寬度不是正整數時報錯" "rc=$RC"
}

t_basic() {
  local in="$WORK/basic/in" out="$WORK/basic/out"
  make_fixtures "$in"
  run "$WORK/basic.log" -w 200 "$in" "$out"
  [ "$RC" -eq 0 ] && ok "基本執行成功" || nok "基本執行成功" "rc=$RC; $(cat "$WORK/basic.log")"

  [ -f "$out/photo.jpg.jpg" ] && [ -f "$out/wide.png.jpg" ] && [ -f "$out/clip.mp4.jpg" ] \
    && ok "每個圖片與影片都有縮圖" || nok "每個圖片與影片都有縮圖" "$(ls "$out")"

  [ "$(width_of "$out/photo.jpg.jpg")" = 200 ] && [ "$(height_of "$out/photo.jpg.jpg")" = 150 ] \
    && ok "圖片縮到指定寬度並維持比例 (800x600 -> 200x150)" \
    || nok "圖片縮到指定寬度並維持比例" "$(width_of "$out/photo.jpg.jpg")x$(height_of "$out/photo.jpg.jpg")"

  [ "$(width_of "$out/clip.mp4.jpg")" = 200 ] && ok "影片縮圖也縮到指定寬度" \
    || nok "影片縮圖也縮到指定寬度" "w=$(width_of "$out/clip.mp4.jpg")"

  local c; c=$(color_at "$out/clip.mp4.jpg" 100 75)
  [ "$c" = green ] && ok "影片縮圖是中間那一格（紅/綠/藍影片取到綠色）" || nok "影片縮圖是中間那一格" "color=$c"

  [ ! -e "$out/notes.txt.jpg" ] && ok "非圖片/影片檔案被忽略" || nok "非圖片/影片檔案被忽略"

  if [ -f "$out/overview.jpg" ] && [ "$(width_of "$out/overview.jpg")" -gt 400 ]; then
    ok "產生總覽圖，且寬度足以容納多張縮圖"
  else
    nok "產生總覽圖" "$(ls "$out")"
  fi

  local n; n=$(ls "$out" | grep -c '\.jpg$')
  [ "$n" -eq 4 ] && ok "輸出資料夾只有 3 張縮圖加 1 張總覽圖" || nok "輸出檔案數量正確" "n=$n: $(ls "$out")"
}

t_skip() {
  local in="$WORK/basic/in" out="$WORK/basic/out"
  local before_p before_o; before_p=$(mtime "$out/photo.jpg.jpg"); before_o=$(mtime "$out/overview.jpg")
  sleep 1
  run "$WORK/skip.log" -w 200 "$in" "$out"
  if [ "$RC" -eq 0 ] && [ "$(mtime "$out/photo.jpg.jpg")" = "$before_p" ] \
     && [ "$(grep -c '略過（已存在）' "$WORK/skip.log")" -eq 3 ] && grep -q '新產生 0' "$WORK/skip.log"; then
    ok "第二次執行時已做過的縮圖不重做"
  else
    nok "第二次執行時已做過的縮圖不重做" "$(cat "$WORK/skip.log")"
  fi
  [ "$(mtime "$out/overview.jpg")" = "$before_o" ] && ok "沒有變化時總覽圖也不重做" || nok "沒有變化時總覽圖也不重做"
}

t_source_updated() {
  local in="$WORK/basic/in" out="$WORK/basic/out"
  sleep 1
  convert -size 400x400 xc:blue "$in/photo.jpg"
  run "$WORK/upd.log" -w 200 "$in" "$out"
  local c; c=$(color_at "$out/photo.jpg.jpg" 10 10)
  if [ "$RC" -eq 0 ] && [ "$c" = blue ] && grep -q '新產生 1' "$WORK/upd.log"; then
    ok "原始檔更新後只重做那一張"
  else
    nok "原始檔更新後只重做那一張" "color=$c; $(cat "$WORK/upd.log")"
  fi
}

t_new_file() {
  local in="$WORK/basic/in" out="$WORK/basic/out"
  local before; before=$(mtime "$out/overview.jpg")
  sleep 1
  convert -size 300x300 xc:green "$in/added.gif"
  run "$WORK/add.log" -w 200 "$in" "$out"
  if [ "$RC" -eq 0 ] && [ -f "$out/added.gif.jpg" ] && [ "$(mtime "$out/overview.jpg")" != "$before" ]; then
    ok "新增檔案後補做縮圖並更新總覽圖"
  else
    nok "新增檔案後補做縮圖並更新總覽圖" "$(cat "$WORK/add.log")"
  fi
}

t_removed_file() {
  local in="$WORK/basic/in" out="$WORK/basic/out"
  local before; before=$(mtime "$out/overview.jpg")
  sleep 1
  rm "$in/added.gif"
  run "$WORK/rm.log" -w 200 "$in" "$out"
  if [ "$RC" -eq 0 ] && [ "$(mtime "$out/overview.jpg")" != "$before" ] && grep -q '（3 張）' "$WORK/rm.log"; then
    ok "原始檔刪除後總覽圖重做且不再包含它"
  else
    nok "原始檔刪除後總覽圖重做且不再包含它" "$(cat "$WORK/rm.log")"
  fi
}

t_force() {
  local in="$WORK/basic/in" out="$WORK/basic/out"
  run "$WORK/force.log" -f -w 200 "$in" "$out"
  [ "$RC" -eq 0 ] && grep -q '新產生 3' "$WORK/force.log" && ok "-f 強制全部重做" || nok "-f 強制全部重做" "$(cat "$WORK/force.log")"
}

t_tricky_names() {
  local in="$WORK/names/in" out="$WORK/names/out"
  mkdir -p "$in"
  convert -size 640x480 xc:red "$in/my photo 100%.JPG"
  convert -size 640x480 xc:blue "$in/same.png"
  convert -size 640x480 xc:green "$in/same.jpg"
  convert -size 640x480 xc:red "$in/-dash.jpeg"
  make_video_rgb "$in/影片 片段.MOV"
  run "$WORK/names.log" -w 160 "$in" "$out"
  if [ "$RC" -eq 0 ] && [ -f "$out/my photo 100%.JPG.jpg" ] && [ -f "$out/-dash.jpeg.jpg" ] \
     && [ -f "$out/影片 片段.MOV.jpg" ] && [ -f "$out/overview.jpg" ]; then
    ok "支援空白、%、中文、開頭是 - 的檔名與大寫副檔名"
  else
    nok "支援特殊檔名與大寫副檔名" "$(cat "$WORK/names.log"); $(ls "$out")"
  fi
  if [ "$(color_at "$out/same.png.jpg" 5 5)" = blue ] && [ "$(color_at "$out/same.jpg.jpg" 5 5)" = green ]; then
    ok "同名不同副檔名 (same.png / same.jpg) 不會互相覆蓋"
  else
    nok "同名不同副檔名不會互相覆蓋"
  fi
}

t_no_upscale() {
  local in="$WORK/small/in" out="$WORK/small/out"
  mkdir -p "$in"
  convert -size 50x40 xc:red "$in/tiny.png"
  ffmpeg -nostdin -loglevel error -y -f lavfi -i "color=c=red:s=64x48:d=1:r=10" -pix_fmt yuv420p "$in/tiny.mp4"
  run "$WORK/small.log" -w 320 "$in" "$out"
  [ "$(width_of "$out/tiny.png.jpg")" = 50 ] && [ "$(width_of "$out/tiny.mp4.jpg")" = 64 ] \
    && ok "比指定寬度小的圖片/影片不會被放大" \
    || nok "比指定寬度小的不會被放大" "$(width_of "$out/tiny.png.jpg") $(width_of "$out/tiny.mp4.jpg")"
}

t_alpha_and_animated() {
  local in="$WORK/alpha/in" out="$WORK/alpha/out"
  mkdir -p "$in"
  convert -size 200x200 xc:none "$in/transparent.png"
  convert -size 100x100 xc:red xc:blue -loop 0 "$in/anim.gif"
  run "$WORK/alpha.log" -w 100 "$in" "$out"
  local c; c=$(convert "$out/transparent.png.jpg" -format '%[fx:int(255*p{5,5}.r)]' info:)
  local frames; frames=$(identify "$out/anim.gif.jpg" | wc -l)
  if [ "$RC" -eq 0 ] && [ "$c" -gt 240 ] && [ "$frames" -eq 1 ] && [ "$(color_at "$out/anim.gif.jpg" 5 5)" = red ]; then
    ok "透明背景轉白底、動畫 GIF 取第一格且只輸出一張"
  else
    nok "透明背景與動畫 GIF 處理" "r=$c frames=$frames; $(cat "$WORK/alpha.log")"
  fi
}

t_broken_file() {
  local in="$WORK/broken/in" out="$WORK/broken/out"
  mkdir -p "$in"
  convert -size 300x300 xc:red "$in/good.jpg"
  echo "garbage" > "$in/bad.mp4"
  echo "garbage" > "$in/bad.png"
  run "$WORK/broken.log" "$in" "$out"
  if [ "$RC" -eq 1 ] && [ -f "$out/good.jpg.jpg" ] && [ ! -e "$out/bad.mp4.jpg" ] && [ ! -e "$out/bad.png.jpg" ] \
     && grep -q '失敗 2' "$WORK/broken.log" && [ -f "$out/overview.jpg" ] \
     && [ -z "$(find "$out" -name '.tmp.*')" ]; then
    ok "壞檔回報失敗(結束碼 1)，其他檔照常處理且不留暫存檔"
  else
    nok "壞檔處理" "rc=$RC; $(cat "$WORK/broken.log"); $(ls -a "$out")"
  fi
}

t_empty_dir() {
  mkdir -p "$WORK/empty/in"
  run "$WORK/empty.log" "$WORK/empty/in" "$WORK/empty/out"
  [ "$RC" -eq 0 ] && [ -d "$WORK/empty/out" ] && [ ! -e "$WORK/empty/out/overview.jpg" ] \
    && ok "空資料夾：正常結束、不產生總覽圖" || nok "空資料夾處理" "rc=$RC"
}

t_options() {
  local in="$WORK/basic/in" out="$WORK/opt/out"
  run "$WORK/opt.log" -q -c 2 -o "all.jpg" -w 100 "$in" "$out"
  # 3 張縮圖、每列 2 張 → 2 列，寬約 2 格
  local w; w=$(width_of "$out/all.jpg")
  if [ "$RC" -eq 0 ] && [ ! -s "$WORK/opt.log" ] && [ -f "$out/all.jpg" ] && [ "$w" -lt 300 ] && [ "$w" -gt 200 ]; then
    ok "-q 安靜、-c 欄數、-o 總覽檔名都有效"
  else
    nok "-q -c -o 選項" "rc=$RC w=$w; $(cat "$WORK/opt.log")"
  fi
}

t_usage; t_bad_input; t_bad_width
t_basic; t_skip; t_source_updated; t_new_file; t_removed_file; t_force
t_tricky_names; t_no_upscale; t_alpha_and_animated; t_broken_file; t_empty_dir; t_options

echo
echo "結果：$pass 通過，$fail 失敗（共 $((pass + fail)) 項）"
if [ "$fail" -gt 0 ]; then printf '  失敗: %s\n' "${failed_names[@]}"; exit 1; fi
