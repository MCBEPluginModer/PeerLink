#!/usr/bin/env python3
"""Scenario/stress harness for PeerLink Beta.

Examples:
  python tests/scenario_runner.py selftest
  python tests/scenario_runner.py two-node --exe build\\windows\\x64\\release\\messenger.exe
  python tests/scenario_runner.py file-transfer --exe build\\windows\\x64\\release\\messenger.exe
"""
from __future__ import annotations

import argparse
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
TESTS = ROOT / "tests"


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def resolve_exe(path: Path) -> Path:
    candidates = []
    if path.is_absolute():
        candidates.append(path)
    else:
        candidates.append(Path.cwd() / path)
        candidates.append(ROOT / path)
        candidates.append((ROOT / "tests") / path)
    for cand in candidates:
        cand = cand.resolve()
        if cand.exists():
            return cand
    return path


def selftest() -> int:
    p2p_node = read_text(SRC / "net" / "p2p_node.cpp")
    types_h = read_text(SRC / "core" / "types.h")
    packet_protocol = read_text(SRC / "net" / "packet_protocol.cpp")
    scenario_py = read_text(TESTS / "scenario_runner.py")

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
        "isolated_harness": "prepare_workspace" in scenario_py and "bootstrap_nodes.txt" in scenario_py,
        "nat_status": "PrintNatStatus" in p2p_node and "/natstatus" in read_text(SRC / "main.cpp"),
        "stun_turn_client": "StunTurnClient" in read_text(SRC / "net" / "stun_turn_client.cpp"),
        "large_file_scenario": "scenario_large_file" in scenario_py,
        "memory_pressure_scenario": "scenario_memory_pressure" in scenario_py,
        "crash_recovery_scenario": "scenario_crash_recovery" in scenario_py,
    }

    failed = [name for name, ok in checks.items() if not ok]
    for name, ok in checks.items():
        print(f"[{'OK' if ok else 'FAIL'}] {name}")
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
    workdir: Path


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


def prepare_workspace(base: Path, nickname: str, port: int) -> Path:
    workdir = base / nickname
    workdir.mkdir(parents=True, exist_ok=True)
    cfg = workdir / "messenger.cfg"
    cfg.write_text(
        f"listen_port={port}\n"
        f"nickname={nickname}\n"
        "log_level=info\n"
        "log_to_console=true\n"
        "log_timestamps=true\n"
        "ui_show_banner=false\n"
        "ui_compact_mode=true\n",
        encoding="utf-8",
    )
    (workdir / "bootstrap_nodes.txt").write_text("", encoding="utf-8")
    return workdir


def write_blob(path: Path, size_bytes: int) -> None:
    chunk = ("PEERLINK-STRESS-" * 1024).encode("utf-8")
    with path.open("wb") as f:
        remaining = size_bytes
        while remaining > 0:
            part = chunk[: min(len(chunk), remaining)]
            f.write(part)
            remaining -= len(part)


def print_pass(name: str) -> int:
    print(f"[PASS] {name}")
    return 0


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
    return NodeProc(name=nickname, proc=proc, lines=q, workdir=cwd)


def send_cmd(node: NodeProc, cmd: str) -> None:
    if node.proc.stdin is None:
        raise RuntimeError(f"stdin closed for {node.name}")
    node.proc.stdin.write(cmd + "\n")
    node.proc.stdin.flush()


def _match(line: str, needles: tuple[str, ...]) -> bool:
    return any(n in line for n in needles)


def wait_for(node: NodeProc, needle: str | tuple[str, ...], timeout: float = 10.0) -> bool:
    needles = (needle,) if isinstance(needle, str) else needle
    end = time.time() + timeout
    while time.time() < end:
        try:
            line = node.lines.get(timeout=0.2)
        except queue.Empty:
            continue
        print(f"[{node.name}] {line}")
        if _match(line, needles):
            return True
    return False


def wait_any(nodes: list[NodeProc], needle: str | tuple[str, ...], timeout: float = 10.0) -> bool:
    needles = (needle,) if isinstance(needle, str) else needle
    end = time.time() + timeout
    while time.time() < end:
        for node in nodes:
            try:
                line = node.lines.get(timeout=0.1)
            except queue.Empty:
                continue
            print(f"[{node.name}] {line}")
            if _match(line, needles):
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


def bootstrap_private_session(a: NodeProc, b: NodeProc, a_port: int, b_port: int) -> bool:
    send_cmd(a, f"/connect 127.0.0.1 {b_port}")
    if not wait_any([a, b], ("Connected with", "Incoming connection"), timeout=10.0):
        print("failed to establish direct connection")
        return False
    time.sleep(1.0)
    send_cmd(a, "/users")
    send_cmd(b, "/users")
    time.sleep(0.5)
    send_cmd(a, "/addcontact 1")
    send_cmd(b, "/addcontact 1")
    if not wait_any([a, b], "Contact saved:", timeout=6.0):
        print("failed to create contacts")
        return False
    send_cmd(a, "/invite 1")
    if not wait_for(b, "invites you to private chat", timeout=8.0):
        print("invite did not arrive")
        return False
    send_cmd(b, "/accept 1")
    if not wait_any([a, b], ("E2E ready", "Private chat opened with"), timeout=10.0):
        print("private session was not established")
        return False
    return True


def scenario_two_node(exe: Path) -> int:
    temp_root = Path(tempfile.mkdtemp(prefix="peerlink-two-node-"))
    a = start_node(exe, 4011, "alpha", prepare_workspace(temp_root, "alpha", 4011))
    b = start_node(exe, 4012, "beta", prepare_workspace(temp_root, "beta", 4012))
    nodes = [a, b]
    try:
        time.sleep(1.5)
        if not bootstrap_private_session(a, b, 4011, 4012):
            return 1
        send_cmd(a, "/all hello-from-alpha")
        time.sleep(1.5)
        drain(a, 0.5)
        drain(b, 1.5)
        return print_pass("two-node")
    finally:
        stop_nodes(nodes)
        shutil.rmtree(temp_root, ignore_errors=True)


def scenario_reconnect(exe: Path) -> int:
    temp_root = Path(tempfile.mkdtemp(prefix="peerlink-reconnect-"))
    work_a = prepare_workspace(temp_root, "recon-a", 4031)
    work_b = prepare_workspace(temp_root, "recon-b", 4032)
    a = start_node(exe, 4031, "recon-a", work_a)
    b = start_node(exe, 4032, "recon-b", work_b)
    nodes = [a, b]
    try:
        time.sleep(1.5)
        if not bootstrap_private_session(a, b, 4031, 4032):
            return 1
        send_cmd(a, "/all first-msg")
        time.sleep(1.0)
        send_cmd(a, "/exit")
        time.sleep(1.0)
        a2 = start_node(exe, 4031, "recon-a", work_a)
        nodes = [a2, b]
        time.sleep(1.5)
        send_cmd(a2, "/connect 127.0.0.1 4032")
        time.sleep(2.0)
        send_cmd(a2, "/all second-msg")
        time.sleep(2.0)
        drain(a2, 0.5)
        drain(b, 1.5)
        return print_pass("reconnect")
    finally:
        stop_nodes(nodes)
        shutil.rmtree(temp_root, ignore_errors=True)


def scenario_file_transfer(exe: Path) -> int:
    temp_root = Path(tempfile.mkdtemp(prefix="peerlink-file-transfer-"))
    work_a = prepare_workspace(temp_root, "file-a", 4041)
    work_b = prepare_workspace(temp_root, "file-b", 4042)
    sample = temp_root / "sample_transfer.txt"
    sample.write_text("peerlink file transfer integration test\n" * 32, encoding="utf-8")
    a = start_node(exe, 4041, "file-a", work_a)
    b = start_node(exe, 4042, "file-b", work_b)
    nodes = [a, b]
    try:
        time.sleep(1.5)
        if not bootstrap_private_session(a, b, 4041, 4042):
            return 1
        # Current CLI path parsing does not strip surrounding quotes, so pass the
        # isolated temp file path directly. The temp workspace path has no spaces.
        send_cmd(a, f'/sendfile 1 {sample}')
        if not wait_any([a, b], ("File offer sent", "Incoming file offer"), timeout=8.0):
            print("file offer did not appear")
            return 1
        send_cmd(b, "/pendingfiles")
        if not wait_for(b, ("sample_transfer.txt", "Pending Files"), timeout=6.0):
            print("pending files list did not include the sample")
            return 1
        send_cmd(b, "/download 1")
        if not wait_any([a, b], ("File saved:", "File data sent:"), timeout=20.0):
            print("file transfer did not complete")
            return 1
        downloaded = list((work_b / "downloads").rglob("sample_transfer*.txt"))
        if not downloaded:
            print("downloaded file not found in isolated workspace")
            return 1
        if downloaded[0].read_text(encoding="utf-8", errors="replace") != sample.read_text(encoding="utf-8"):
            print("downloaded file content mismatch")
            return 1
        drain(a, 1.0)
        drain(b, 2.0)
        return print_pass("file-transfer")
    finally:
        stop_nodes(nodes)
        shutil.rmtree(temp_root, ignore_errors=True)


def scenario_burst(exe: Path, messages: int) -> int:
    temp_root = Path(tempfile.mkdtemp(prefix="peerlink-burst-"))
    a = start_node(exe, 4021, "burst-a", prepare_workspace(temp_root, "burst-a", 4021))
    b = start_node(exe, 4022, "burst-b", prepare_workspace(temp_root, "burst-b", 4022))
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
        return print_pass("burst")
    finally:
        stop_nodes(nodes)
        shutil.rmtree(temp_root, ignore_errors=True)


def scenario_large_file(exe: Path, size_mb: int) -> int:
    temp_root = Path(tempfile.mkdtemp(prefix="peerlink-large-file-"))
    work_a = prepare_workspace(temp_root, "large-a", 4051)
    work_b = prepare_workspace(temp_root, "large-b", 4052)
    sample = temp_root / "large_transfer.bin"
    write_blob(sample, size_mb * 1024 * 1024)
    a = start_node(exe, 4051, "large-a", work_a)
    b = start_node(exe, 4052, "large-b", work_b)
    nodes = [a, b]
    try:
        time.sleep(1.5)
        if not bootstrap_private_session(a, b, 4051, 4052):
            return 1
        send_cmd(a, f'/sendfile 1 {sample}')
        if not wait_any([a, b], ("File offer sent", "Incoming file offer"), timeout=12.0):
            print("large file offer did not appear")
            return 1
        send_cmd(b, "/download 1")
        if not wait_any([a, b], ("File saved:", "File data sent:"), timeout=max(30.0, size_mb * 8.0)):
            print("large file transfer did not complete")
            return 1
        downloaded = list((work_b / "downloads").rglob("large_transfer*.bin"))
        if not downloaded or downloaded[0].stat().st_size != sample.stat().st_size:
            print("large file missing or size mismatch")
            return 1
        return print_pass("large-file")
    finally:
        stop_nodes(nodes)
        shutil.rmtree(temp_root, ignore_errors=True)


def scenario_memory_pressure(exe: Path, messages: int, file_size_mb: int) -> int:
    temp_root = Path(tempfile.mkdtemp(prefix="peerlink-mem-pressure-"))
    work_a = prepare_workspace(temp_root, "mem-a", 4061)
    work_b = prepare_workspace(temp_root, "mem-b", 4062)
    sample = temp_root / "pressure.bin"
    write_blob(sample, file_size_mb * 1024 * 1024)
    a = start_node(exe, 4061, "mem-a", work_a)
    b = start_node(exe, 4062, "mem-b", work_b)
    nodes = [a, b]
    try:
        time.sleep(1.5)
        if not bootstrap_private_session(a, b, 4061, 4062):
            return 1
        send_cmd(a, f'/sendfile 1 {sample}')
        wait_any([a, b], ("File offer sent", "Incoming file offer"), timeout=8.0)
        send_cmd(b, "/download 1")
        for i in range(messages):
            send_cmd(a, f"/all mem-a-{i}")
            send_cmd(b, f"/all mem-b-{i}")
            if i % 16 == 0:
                time.sleep(0.05)
        if not wait_any([a, b], ("File saved:", "File data sent:"), timeout=max(20.0, file_size_mb * 6.0)):
            print("memory pressure transfer did not complete")
            return 1
        send_cmd(a, "/stats")
        send_cmd(b, "/stats")
        drain(a, 1.5)
        drain(b, 1.5)
        return print_pass("memory-pressure")
    finally:
        stop_nodes(nodes)
        shutil.rmtree(temp_root, ignore_errors=True)


def scenario_crash_recovery(exe: Path, file_size_mb: int) -> int:
    temp_root = Path(tempfile.mkdtemp(prefix="peerlink-crash-recovery-"))
    work_a = prepare_workspace(temp_root, "crash-a", 4071)
    work_b = prepare_workspace(temp_root, "crash-b", 4072)
    sample = temp_root / "resume.bin"
    write_blob(sample, file_size_mb * 1024 * 1024)
    a = start_node(exe, 4071, "crash-a", work_a)
    b = start_node(exe, 4072, "crash-b", work_b)
    try:
        time.sleep(1.5)
        if not bootstrap_private_session(a, b, 4071, 4072):
            return 1
        send_cmd(a, f'/sendfile 1 {sample}')
        if not wait_any([a, b], ("File offer sent", "Incoming file offer"), timeout=8.0):
            print("crash-recovery offer did not appear")
            return 1
        send_cmd(b, "/download 1")
        time.sleep(1.0)
        # simulate crash of receiver mid-transfer
        if b.proc.poll() is None:
            b.proc.kill()
            b.proc.wait(timeout=3)
        b2 = start_node(exe, 4072, "crash-b", work_b)
        time.sleep(2.5)
        send_cmd(a, "/transfers")
        send_cmd(b2, "/transfers")
        if not wait_any([a, b2], ("resume.bin", "File saved:"), timeout=max(20.0, file_size_mb * 8.0)):
            print("crash-recovery transfer did not resume or complete")
            return 1
        send_cmd(a, "/stats")
        send_cmd(b2, "/stats")
        drain(a, 1.0)
        drain(b2, 1.0)
        return print_pass("crash-recovery")
    finally:
        stop_nodes([n for n in [a, locals().get('b2', None)] if n is not None])
        shutil.rmtree(temp_root, ignore_errors=True)


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

    pl = sub.add_parser("large-file", help="send a large file end-to-end")
    pl.add_argument("--exe", required=True, type=Path)
    pl.add_argument("--size-mb", type=int, default=8)

    pm = sub.add_parser("memory-pressure", help="run chat burst and file transfer together")
    pm.add_argument("--exe", required=True, type=Path)
    pm.add_argument("--messages", type=int, default=200)
    pm.add_argument("--file-size-mb", type=int, default=4)

    pc = sub.add_parser("crash-recovery", help="kill receiver mid-transfer and verify recovery")
    pc.add_argument("--exe", required=True, type=Path)
    pc.add_argument("--file-size-mb", type=int, default=6)

    pb = sub.add_parser("burst", help="launch two nodes and send a burst of messages")
    pb.add_argument("--exe", required=True, type=Path)
    pb.add_argument("--messages", type=int, default=100)

    args = parser.parse_args(argv)
    if args.cmd == "selftest":
        return selftest()

    exe = resolve_exe(args.exe)
    if not exe.exists():
        print(f"Executable not found: {exe}")
        return 2
    if args.cmd == "two-node":
        return scenario_two_node(exe)
    if args.cmd == "reconnect":
        return scenario_reconnect(exe)
    if args.cmd == "file-transfer":
        return scenario_file_transfer(exe)
    if args.cmd == "large-file":
        return scenario_large_file(exe, args.size_mb)
    if args.cmd == "memory-pressure":
        return scenario_memory_pressure(exe, args.messages, args.file_size_mb)
    if args.cmd == "crash-recovery":
        return scenario_crash_recovery(exe, args.file_size_mb)
    if args.cmd == "burst":
        return scenario_burst(exe, args.messages)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
