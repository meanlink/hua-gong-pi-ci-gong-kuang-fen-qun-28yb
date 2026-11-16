#!/usr/bin/env python3
"""封存凭据离线核验工具（仅依赖 Python 标准库）。

用法：
    python verify_seal.py 封存文件.seal.json

核验内容：
- 可信起点 genesis 的固定内容与自哈希；
- 每条凭据的自哈希（检测内容篡改）；
- prev_hash 链接（检测删改断链）；
- seq 连续性（检测缺条/空号/重复）与顺序（检测乱序）；
- 封存终点（检测整段尾部被删）；
- 封存总哈希 seal_hash（检测封存包被改动）。
退出码：0 通过，1 发现问题，2 文件/格式错误。
"""
import hashlib
import json
import sys

GENESIS_SEQ = 0
GENESIS_EVENT = 'chain.genesis'
GENESIS_ACTOR = 'system'
GENESIS_PAYLOAD = {
    'purpose': '工艺复查连续凭据链可信起点',
    'scope': ['dataset.intake', 'job.lifecycle', 'job.approval', 'report.archive', 'seal.lifecycle'],
    'version': 1,
}
GENESIS_AT = 1763000000.0


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      allow_nan=False, separators=(',', ':'))


def entry_hash(seq, event, actor, payload, prev_hash, at):
    return hashlib.sha256(canonical({
        'seq': seq, 'event': event, 'actor': actor, 'payload': payload,
        'prev_hash': prev_hash, 'at': at,
    }).encode('utf-8')).hexdigest()


def genesis_hash():
    return entry_hash(GENESIS_SEQ, GENESIS_EVENT, GENESIS_ACTOR, GENESIS_PAYLOAD, '0' * 64, GENESIS_AT)


def seal_hash(bundle):
    seal = bundle['seal']
    digest = hashlib.sha256()
    for e in sorted(bundle['entries'], key=lambda r: r['seq']):
        digest.update(canonical({
            'seq': e['seq'], 'event': e['event'], 'actor': e['actor'], 'payload': e['payload'],
            'prev_hash': e['prev_hash'], 'entry_hash': e['entry_hash'], 'at': e['at'],
        }).encode('utf-8'))
    digest.update(canonical({
        'seal_code': seal['seal_code'], 'up_to_seq': seal['up_to_seq'],
        'entry_count': seal['up_to_seq'] + 1,
    }).encode('utf-8'))
    return digest.hexdigest()


def verify(path):
    with open(path, 'rb') as f:
        bundle = json.loads(f.read().decode('utf-8'))
    issues = []
    if bundle.get('format') != 'credential-seal/v1':
        return ['封存包 format 不是 credential-seal/v1，无法识别'], None
    seal, entries = bundle['seal'], bundle['entries']

    raw_seqs = [e['seq'] for e in entries]
    if raw_seqs != sorted(raw_seqs):
        issues.append('乱序：entries 未按 seq 升序排列')
    seqs = sorted(raw_seqs)
    if seqs and seqs[0] != GENESIS_SEQ:
        issues.append(f'缺少可信起点 genesis（seq=0），首条 seq={seqs[0]}')
    elif entries:
        g = next((e for e in entries if e['seq'] == GENESIS_SEQ), None)
        if g and g['entry_hash'] != genesis_hash():
            issues.append('genesis 凭据与固定可信起点内容不符（起点被篡改）')

    missing = sorted(set(range(0, seqs[-1] + 1)) - set(seqs)) if seqs else list(range(0, seal['up_to_seq'] + 1))
    if missing:
        issues.append(f"缺条/空号：缺少 seq {missing[:10]}{'…' if len(missing) > 10 else ''}，共 {len(missing)} 条")
    dup = sorted({s for s in seqs if seqs.count(s) > 1})
    if dup:
        issues.append(f'seq 重复：{dup}')

    prev = '0' * 64
    by_seq = {e['seq']: e for e in entries}
    for seq in seqs:
        e = by_seq[seq]
        if entry_hash(seq, e['event'], e['actor'], e['payload'], e['prev_hash'], e['at']) != e['entry_hash']:
            issues.append(f'seq={seq} 自哈希不一致（内容被篡改）')
        if e['prev_hash'] != prev:
            issues.append(f'seq={seq} prev_hash 断链（前序凭据被删改）')
        prev = e['entry_hash']

    if seqs and seqs[-1] != seal['up_to_seq']:
        issues.append(f"整段尾部被删：封存声明到 seq={seal['up_to_seq']}，实际末条 seq={seqs[-1]}")
    if seal.get('entry_count') != len(entries):
        issues.append(f"封存条数不符：声明 {seal.get('entry_count')}，实际 {len(entries)}")
    actual = seal_hash(bundle)
    if actual != seal.get('seal_hash'):
        issues.append(f"封存总哈希不一致：声明 {str(seal.get('seal_hash'))[:16]}… 实算 {actual[:16]}…（封存包被改动）")
    return issues, seal


def main():
    if len(sys.argv) != 2:
        print('用法：python verify_seal.py 封存文件.seal.json')
        sys.exit(2)
    try:
        issues, seal = verify(sys.argv[1])
    except FileNotFoundError:
        print(f'文件不存在：{sys.argv[1]}')
        sys.exit(2)
    except Exception as exc:
        print(f'封存文件无法解析：{exc}')
        sys.exit(2)
    if issues:
        print('核验未通过，发现以下问题：')
        for i, msg in enumerate(issues, 1):
            print(f'  {i}. {msg}')
        sys.exit(1)
    print('核验通过 ✓')
    print(f"  封存编号：{seal['seal_code']}")
    print(f"  凭据范围：seq 0 ~ {seal['up_to_seq']}（共 {seal['entry_count']} 条）")
    print(f"  封存哈希：{seal['seal_hash']}")
    sys.exit(0)


if __name__ == '__main__':
    main()
