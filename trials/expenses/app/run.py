"""啟動記帳網頁：python run.py [--port 5000] [--no-browser]"""
import argparse
import threading
import webbrowser

from expenses.app import create_app


def main():
    p = argparse.ArgumentParser(description="旅行記帳網頁")
    p.add_argument("--port", type=int, default=5000)
    p.add_argument("--no-browser", action="store_true", help="不要自動開啟瀏覽器")
    args = p.parse_args()

    app = create_app()
    url = f"http://127.0.0.1:{args.port}/"
    if not args.no_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    print(f"記帳網頁：{url}  （Ctrl+C 結束）")
    # 只綁定 127.0.0.1，同網路的其他人連不到
    app.run(host="127.0.0.1", port=args.port, debug=False)


if __name__ == "__main__":
    main()
