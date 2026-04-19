#!/usr/bin/env python3
"""Scenario/stress harness for PeerLink Beta 1.1.

This runner can:
- perform static capability/file-transfer sanity checks without a built binary
- launch 2+ messenger processes and drive basic scenarios over stdin/stdout
- run message burst, reconnect, and file-transfer integration scenarios

Examples:
  python tests/scenario_runner.py selftest
  python tests/scenario_runner.py two-node --exe build\\windows\\x64\\release\\messenger.exe
  python tests/scenario_runner.py burst --exe build\\windows\\x64\\release\\messenger.exe --messages 100
"""
from __future__ import annotations

import argparse
import os
import queue
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def selftest() -> int:
    p2p_node = read_text(SRC / "net" / "p2p_node.cpp")
    types_h = read_text(SRC / "core" / "types.h")
    packet_protocol = read_text(SRC / "net" / "packet_protocol.cpp")

    checks = {
        "protocol_v4": "kProtocolVersion = 4" in types_h,
        "hello_capabilities": "capabilityFlags" in types_h and "SerializeHello" in packet_protocol,
        "file_transfer_v2_offer": "[[FILEOFFER]]" in p2p_node and "fileChecksum" in p2p_node,
        "streaming_send": "std::ifstream in(transfer.sourcePath" in p2p_node,
        "streaming_receive": ".part" in p2p_node and "std::ofstream out(transfer.tempPath" in p2p_node,
        "anti_replay": "MarkRecentIncomingMessage" in p2p_node and "MarkRecentControlReplay" in p2p_node,
        "stats": "PrintStats" in p2p_node and "/stats" in read_text(SRC / "main.cpp"),
        "handshake_guard": "CleanupPendingHandshakes" in p2p_node and "maxPendingHandshakes_" in read_text(SRC / "net" / "p2p_node.h"),
        "history_usability": "SearchConversationHistoryByContactIndex" in p2p_node and "ExportConversationHistoryByContactIndex" in p2p_node,
    }

    failed = [name for name, ok in checks.items() if not ok]
    for name, ok in checks.items():
        print(f"[{ 'OK' if ok else 'FAIL' }] {name}")
    if failed:
        print("Selftest failed:", ", ".join(failed))
        return 1
    print("Selftest passed.")
    return 0


@dataclass
class NodeProc:
    name: str
    proc: subprocess.Popen
    lines: "queue.Queue[str]"


def _reader_thread(stream, out_queue: "queue.Queue[str]") -> None:
    try:
        for line in iter(stream.readline, ""):
            if not line:
                break
            out_queue.put(line.rstrip())
    finally:
        try:
            stream.close()
        except Exception:
            pass


def start_node(exe: Path, port: int, nickname: str, cwd: Path) -> NodeProc:
    proc = subprocess.Popen(
        [str(exe), str(port), nickname],
        cwd=str(cwd),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    q: "queue.Queue[str]" = queue.Queue()
    t = threading.Thread(target=_reader_thread, args=(proc.stdout, q), daemon=True)
    t.start()
    return NodeProc(name=nickname, proc=proc, lines=q)


def send_cmd(node: NodeProc, cmd: str) -> None:
    if node.proc.stdin is None:
        raise RuntimeError(f"stdin closed for {node.name}")
    node.proc.stdin.write(cmd + "\n")
    node.proc.stdin.flush()


def wait_for(node: NodeProc, needle: str, timeout: float = 10.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            line = node.lines.get(timeout=0.2)
        except queue.Empty:
            continue
        print(f"[{node.name}] {line}")
        if needle in line:
            return True
    return False


def drain(node: NodeProc, seconds: float = 1.0) -> None:
    end = time.time() + seconds
    while time.time() < end:
        try:
            line = node.lines.get(timeout=0.1)
        except queue.Empty:
            continue
        print(f"[{node.name}] {line}")


def stop_nodes(nodes: list[NodeProc]) -> None:
    for node in nodes:
        try:
            send_cmd(node, "/exit")
        except Exception:
            pass
    time.sleep(0.5)
    for node in nodes:
        if node.proc.poll() is None:
            node.proc.terminate()
    for node in nodes:
        try:
            node.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            node.proc.kill()


def scenario_two_node(exe: Path) -> int:
    workdir = ROOT
    a = start_node(exe, 4011, "alpha", workdir)
    b = start_node(exe, 4012, "beta", workdir)
    nodes = [a, b]
    try:
        time.sleep(1.5)
        send_cmd(a, "/connect 127.0.0.1 4012")
        ok = wait_for(a, "Connected", timeout=8.0) or wait_for(b, "Incoming connection", timeout=8.0)
        if not ok:
            print("Two-node scenario: failed to connect")
            return 1
        send_cmd(a, "/all hello-from-alpha")
        time.sleep(1.5)
        drain(a, 0.5)
        drain(b, 1.5)
        return 0
    finally:
        stop_nodes(nodes)


def scenario_reconnect(exe: Path) -> int:
    workdir = ROOT
    a = start_node(exe, 4031, "recon-a", workdir)
    b = start_node(exe, 4032, "recon-b", workdir)
    nodes = [a, b]
    try:
        time.sleep(1.5)
        send_cmd(a, "/connect 127.0.0.1 4032")
        time.sleep(2.0)
        send_cmd(a, "/all first-msg")
        time.sleep(1.0)
        send_cmd(a, "/exit")
        time.sleep(1.0)
        a2 = start_node(exe, 4031, "recon-a", workdir)
        nodes = [a2, b]
        time.sleep(1.5)
        send_cmd(a2, "/connect 127.0.0.1 4032")
        time.sleep(2.0)
        send_cmd(a2, "/all second-msg")
        time.sleep(2.0)
        drain(a2, 0.5)
        drain(b, 1.5)
        return 0
    finally:
        stop_nodes(nodes)


def scenario_file_transfer(exe: Path) -> int:
    workdir = ROOT
    sample = ROOT / "tests" / "sample_transfer.txt"
    sample.write_text("peerlink file transfer integration test\n" * 32, encoding="utf-8")
    a = start_node(exe, 4041, "file-a", workdir)
    b = start_node(exe, 4042, "file-b", workdir)
    nodes = [a, b]
    try:
        time.sleep(1.5)
        send_cmd(a, "/connect 127.0.0.1 4042")
        time.sleep(2.0)
        send_cmd(a, f"/sendfile 1 {sample}")
        time.sleep(2.0)
        send_cmd(b, "/pendingfiles")
        time.sleep(1.0)
        send_cmd(b, "/download 1")
        time.sleep(3.0)
        drain(a, 1.0)
        drain(b, 2.0)
        return 0
    finally:
        stop_nodes(nodes)


def scenario_burst(exe: Path, messages: int) -> int:
    workdir = ROOT
    a = start_node(exe, 4021, "burst-a", workdir)
    b = start_node(exe, 4022, "burst-b", workdir)
    nodes = [a, b]
    try:
        time.sleep(1.5)
        send_cmd(a, "/connect 127.0.0.1 4022")
        time.sleep(2.0)
        for i in range(messages):
            send_cmd(a, f"/all burst-{i}")
            if i % 10 == 0:
                time.sleep(0.1)
        time.sleep(3.0)
        drain(a, 1.0)
        drain(b, 2.0)
        return 0
    finally:
        stop_nodes(nodes)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="PeerLink scenario/stress runner")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("selftest", help="static code-level sanity checks")

    p2 = sub.add_parser("two-node", help="launch two nodes and perform a basic connectivity scenario")
    p2.add_argument("--exe", required=True, type=Path)

    pr = sub.add_parser("reconnect", help="restart one peer and reconnect")
    pr.add_argument("--exe", required=True, type=Path)

    pf = sub.add_parser("file-transfer", help="send a small file end-to-end")
    pf.add_argument("--exe", required=True, type=Path)

    pb = sub.add_parser("burst", help="launch two nodes and send a burst of messages")
    pb.add_argument("--exe", required=True, type=Path)
    pb.add_argument("--messages", type=int, default=100)

    args = parser.parse_args(argv)
    if args.cmd == "selftest":
        return selftest()
    if not args.exe.exists():
        print(f"Executable not found: {args.exe}")
        return 2
    if args.cmd == "two-node":
        return scenario_two_node(args.exe)
    if args.cmd == "reconnect":
        return scenario_reconnect(args.exe)
    if args.cmd == "file-transfer":
        return scenario_file_transfer(args.exe)
    if args.cmd == "burst":
        return scenario_burst(args.exe, args.messages)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
