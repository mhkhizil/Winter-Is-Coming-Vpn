#!/usr/bin/env python3
# Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
"""Throwaway SMTP server for development and tests.

Speaks just enough SMTP for vpnd's reminder mail (EHLO/MAIL/RCPT/DATA/QUIT, plus
AUTH LOGIN if offered) and writes every message to a directory as
<recipient>-<n>.eml. Used by scripts/verify-reminders.ps1 and handy when you want
to see the reminder text without sending real mail.

  python scripts/fake_smtp.py --port 2525 --outdir out/mail
"""
import argparse
import os
import socketserver
import sys


class Handler(socketserver.StreamRequestHandler):
    outdir = "."
    counter = 0

    def reply(self, text: str) -> None:
        self.wfile.write((text + "\r\n").encode())
        self.wfile.flush()

    def handle(self) -> None:
        self.reply("220 fake-smtp ready")
        rcpt = "unknown"
        while True:
            line = self.rfile.readline()
            if not line:
                return
            command = line.decode("utf-8", "replace").strip()
            upper = command.upper()
            if upper.startswith("EHLO") or upper.startswith("HELO"):
                self.reply("250-fake-smtp")
                self.reply("250-AUTH LOGIN")
                self.reply("250 OK")
            elif upper.startswith("AUTH"):
                self.reply("334 VXNlcm5hbWU6")
                self.rfile.readline()
                self.reply("334 UGFzc3dvcmQ6")
                self.rfile.readline()
                self.reply("235 authenticated")
            elif upper.startswith("MAIL FROM"):
                self.reply("250 OK")
            elif upper.startswith("RCPT TO"):
                rcpt = command.split(":", 1)[1].strip().strip("<>")
                self.reply("250 OK")
            elif upper.startswith("DATA"):
                self.reply("354 end with <CRLF>.<CRLF>")
                lines = []
                while True:
                    raw = self.rfile.readline()
                    if not raw:
                        break
                    text = raw.decode("utf-8", "replace")
                    if text.strip() == ".":
                        break
                    lines.append(text[1:] if text.startswith("..") else text)
                Handler.counter += 1
                safe = "".join(c if c.isalnum() or c in "._@-" else "_" for c in rcpt)
                path = os.path.join(Handler.outdir, f"{safe}-{Handler.counter}.eml")
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write("".join(lines))
                print(f"captured {path}", flush=True)
                self.reply("250 queued")
            elif upper.startswith("QUIT"):
                self.reply("221 bye")
                return
            elif upper.startswith("RSET") or upper.startswith("NOOP"):
                self.reply("250 OK")
            else:
                self.reply("250 OK")


def main() -> int:
    parser = argparse.ArgumentParser(description="fake SMTP capture server")
    parser.add_argument("--port", type=int, default=2525)
    parser.add_argument("--outdir", default="out/mail")
    args = parser.parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    Handler.outdir = args.outdir
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(("127.0.0.1", args.port), Handler) as server:
        print(f"fake-smtp listening on 127.0.0.1:{args.port}, writing to {args.outdir}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
