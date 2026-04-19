
#!/usr/bin/env python3
import argparse, pathlib, random, subprocess, time

def safe_send(proc, cmd):
    try:
        if proc.poll() is not None or proc.stdin is None:
            return False
        proc.stdin.write(cmd + "
")
        proc.stdin.flush()
        return True
    except Exception:
        return False

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", required=True)
    ap.add_argument("--peers", type=int, default=50)
    ap.add_argument("--base-port", type=int, default=9000)
    ap.add_argument("--duration-min", type=int, default=15)
    ap.add_argument("--sample-file", default="sample_transfer.txt")
    args = ap.parse_args()
    exe = pathlib.Path(args.exe).resolve()
    procs = []
    try:
        print('[INFO] starting peers...')
        for i in range(args.peers):
            p = subprocess.Popen([str(exe), str(args.base_port+i), f'peer-{i+1}'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            procs.append(p)
            time.sleep(0.1)
        for p in procs[1:]:
            safe_send(p, f'/connect 127.0.0.1 {args.base_port}')
            time.sleep(0.02)
        time.sleep(6)
        end = time.time() + args.duration_min*60
        posts = 0
        files = 0
        cycles = 0
        while time.time() < end:
            alive = [p for p in procs if p.poll() is None]
            if not alive: break
            author = random.choice(alive)
            safe_send(author, f'/post "Mixed {posts+1}" "body {posts+1}"')
            posts += 1
            if posts % 5 == 0 and len(alive) > 1:
                safe_send(alive[0], f'/sendfile 1 {args.sample_file}')
                files += 1
            if posts % 10 == 0 and len(alive) > 5:
                victim = random.choice(alive[1:])
                safe_send(victim, '/exit')
                time.sleep(1)
                cycles += 1
            time.sleep(1)
        print(f'[PASS] mixed stress finished posts={posts} files={files} reconnect_ops={cycles}')
    finally:
        for p in procs:
            safe_send(p, '/exit')
        time.sleep(1)
        for p in procs:
            try:
                if p.poll() is None:
                    p.terminate()
            except Exception:
                pass

if __name__ == '__main__':
    main()
