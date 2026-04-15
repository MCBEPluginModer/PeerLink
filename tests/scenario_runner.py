import argparse
import subprocess
import sys
import time
from pathlib import Path


def write_line(proc, line: str):
    proc.stdin.write((line + "\n").encode("utf-8"))
    proc.stdin.flush()


def launch(binary: str, port: int, nickname: str, cwd: Path):
    return subprocess.Popen(
        [binary, str(port), nickname],
        cwd=str(cwd),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


def smoke_two_peers(binary: str, cwd: Path):
    a = launch(binary, 9101, "testA", cwd)
    b = launch(binary, 9102, "testB", cwd)
    try:
        time.sleep(1.0)
        write_line(a, "/connect 127.0.0.1 9102")
        time.sleep(1.0)
        write_line(a, "/users")
        write_line(b, "/users")
        time.sleep(1.0)
        write_line(a, "/exit")
        write_line(b, "/exit")
        a.wait(timeout=10)
        b.wait(timeout=10)
        return 0
    finally:
        for p in (a, b):
            if p.poll() is None:
                p.kill()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run basic messenger scenario tests")
    parser.add_argument("--binary", default="messenger.exe", help="Path to built messenger binary")
    parser.add_argument("--cwd", default=".", help="Working directory for spawned peers")
    parser.add_argument("--scenario", default="smoke-two-peers", choices=["smoke-two-peers"])
    args = parser.parse_args()

    cwd = Path(args.cwd).resolve()
    if args.scenario == "smoke-two-peers":
        return smoke_two_peers(args.binary, cwd)
    return 1


if __name__ == "__main__":
    sys.exit(main())
