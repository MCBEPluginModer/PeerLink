#!/usr/bin/env python3
import argparse
import pathlib
import random
import subprocess
import sys
import time
from dataclasses import dataclass


@dataclass
class PeerProc:
    name: str
    proc: subprocess.Popen
    log_path: pathlib.Path


def safe_send(peer: PeerProc, cmd: str) -> bool:
    try:
        if peer.proc.poll() is not None:
            return False
        if peer.proc.stdin is None:
            return False
        peer.proc.stdin.write(cmd + "\n")
        peer.proc.stdin.flush()
        return True
    except Exception:
        return False


def start_peer(exe: pathlib.Path, workdir: pathlib.Path, port: int, name: str) -> PeerProc:
    workdir.mkdir(parents=True, exist_ok=True)
    log_path = workdir / f"{name}.log"
    log_file = log_path.open("w", encoding="utf-8", errors="replace")

    proc = subprocess.Popen(
        [str(exe), str(port), name],
        stdin=subprocess.PIPE,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        text=True,
        cwd=str(workdir),
    )
    return PeerProc(name=name, proc=proc, log_path=log_path)


def stop_peer(peer: PeerProc) -> None:
    try:
        safe_send(peer, "/exit")
    except Exception:
        pass
    time.sleep(0.3)
    try:
        if peer.proc.poll() is None:
            peer.proc.terminate()
    except Exception:
        pass


def read_log(path: pathlib.Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", required=True, help="Path to messenger.exe")
    ap.add_argument("--relay-port", type=int, default=9100)
    ap.add_argument("--author-port", type=int, default=9101)
    ap.add_argument("--receiver-port", type=int, default=9102)
    ap.add_argument("--posts", type=int, default=10)
    ap.add_argument("--min-delay-ms", type=int, default=200)
    ap.add_argument("--max-delay-ms", type=int, default=700)
    ap.add_argument("--work-root", default="anonymity_test_run", help="Directory for peer profiles/logs")
    args = ap.parse_args()

    exe = pathlib.Path(args.exe).resolve()
    if not exe.exists():
        print(f"[FAIL] executable not found: {exe}")
        return 1

    work_root = pathlib.Path(args.work_root).resolve()
    relay_dir = work_root / "relay"
    author_dir = work_root / "author"
    receiver_dir = work_root / "receiver"

    relay = None
    author = None
    receiver = None

    try:
        print("[INFO] starting relay...")
        relay = start_peer(exe, relay_dir, args.relay_port, "relay-node")
        time.sleep(1.0)

        print("[INFO] starting author...")
        author = start_peer(exe, author_dir, args.author_port, "author-node")
        time.sleep(1.0)

        print("[INFO] starting receiver...")
        receiver = start_peer(exe, receiver_dir, args.receiver_port, "receiver-node")
        time.sleep(1.0)

        print("[INFO] connecting author -> relay")
        safe_send(author, f"/connect 127.0.0.1 {args.relay_port}")
        time.sleep(1.0)

        print("[INFO] connecting receiver -> relay")
        safe_send(receiver, f"/connect 127.0.0.1 {args.relay_port}")
        time.sleep(4.0)

        print("[INFO] publishing test posts...")
        for i in range(args.posts):
            title = f"Anonymity Test {i+1}"
            body = f"Origin-hiding probe #{i+1}"
            ok = safe_send(author, f'/post "{title}" "{body}"')
            if not ok:
                print(f"[WARN] failed to send post #{i+1} from author")
            delay_ms = random.randint(args.min_delay_ms, args.max_delay_ms)
            time.sleep(delay_ms / 1000.0)

        print("[INFO] waiting for propagation...")
        time.sleep(8.0)

        relay_log = read_log(relay.log_path)
        author_log = read_log(author.log_path)
        receiver_log = read_log(receiver.log_path)

        print("\n=== Basic log summary ===")
        print(f"relay log:    {relay.log_path}")
        print(f"author log:   {author.log_path}")
        print(f"receiver log: {receiver.log_path}")

        receiver_saw_posts = (
            "Anonymity Test" in receiver_log
            or "Imported" in receiver_log
            or "posts" in receiver_log.lower()
        )

        direct_author_ip_visible = "127.0.0.1:9101" in receiver_log
        direct_author_name_bias = "author-node" in receiver_log and "relay-node" not in receiver_log

        print("\n=== Heuristic result ===")
        if receiver_saw_posts:
            print("[INFO] receiver observed propagated activity/logs")
        else:
            print("[WARN] receiver logs do not clearly show propagated posts")

        if direct_author_ip_visible:
            print("[FAIL] receiver log appears to reference author endpoint directly")
            print("       possible origin leak or direct path visibility")
            result = 2
        elif direct_author_name_bias:
            print("[WARN] receiver log mentions author-node more directly than relay-node")
            print("       inspect logs manually for origin leak")
            result = 0
        else:
            print("[PASS] no obvious direct author endpoint leak found in receiver logs")
            print("       relay-mediated propagation looks plausible")
            result = 0

        print("\n=== Manual checks you should do ===")
        print("1. Open receiver log and verify it does not learn the author's direct endpoint.")
        print("2. Run Wireshark on receiver/relay and confirm receiver only sees relay as previous hop.")
        print("3. Repeat with 20-50 posts and compare timing variance.")
        print("4. Repeat with receiver offline, then back online, and verify post backfill still avoids origin leak.")

        return result

    finally:
        print("\n[INFO] shutting down peers...")
        for peer in [author, receiver, relay]:
            if peer is not None:
                stop_peer(peer)
        time.sleep(1.0)