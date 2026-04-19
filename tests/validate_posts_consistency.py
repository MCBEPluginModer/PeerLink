
#!/usr/bin/env python3
import argparse, pathlib, sys
from collections import Counter

def parse_line(line):
    parts = line.rstrip('
').split('	')
    if len(parts) < 9:
        return None
    return {'postId': parts[1], 'authorId': parts[2]}

def load_ids(path):
    ids=[]
    with path.open('r', encoding='utf-8', errors='replace') as f:
        for line in f:
            if not line.strip() or line.startswith('#'):
                continue
            rec = parse_line(line)
            if rec: ids.append(rec['postId'])
    return ids

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', required=True)
    args = ap.parse_args()
    root = pathlib.Path(args.root)
    feeds = list(root.rglob('*.feed.tsv'))
    if not feeds:
        print('[FAIL] no post feed files found')
        sys.exit(1)
    print(f'[INFO] found {len(feeds)} feed files')
    all_sets=[]
    dup=False
    universe=set()
    for feed in feeds:
        ids=load_ids(feed)
        counter=Counter(ids)
        dups=sum(v-1 for v in counter.values() if v>1)
        if dups: dup=True
        s=set(ids); all_sets.append((feed,s,len(ids),dups)); universe |= s
    for feed,s,total,dups in all_sets:
        print(f'{feed}: posts={total} unique={len(s)} duplicates={dups} missing={len(universe-s)}')
    baseline=all_sets[0][1]
    consistent=all(s==baseline for _,s,_,_ in all_sets)
    if consistent and not dup:
        print('[PASS] all feeds are fully consistent and have no duplicates')
        sys.exit(0)
    print('[WARN] feeds differ or duplicates exist')
    sys.exit(2)

if __name__ == '__main__':
    main()
