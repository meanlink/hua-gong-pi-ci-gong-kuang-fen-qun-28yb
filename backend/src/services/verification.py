"""凭据链与封存包核验。

verify_chain：核验在线库或快照中的连续凭据链。
verify_bundle：只依据另存的封存包本身离线核验，不访问在线库。
问题分类：tamper（篡改）、gap（缺条/空号）、order（乱序）、truncated（整段尾部被删）、genesis（起点不符）。
"""
from sqlalchemy import select
from src.models import Credential, SealEntry
from src.services.credentials import entry_hash, genesis_hash, GENESIS_SEQ


def _check(entries, expected_tail=None, expect_genesis_hash=None):
    """通用链核验。entries 为按 seq 排序前的原始字典/对象列表。"""
    issues = []
    if not entries:
        return {'ok': False, 'issues': [{'type': 'gap', 'detail': '没有任何凭据'}], 'count': 0,
                'head_seq': None, 'tail_hash': None}
    rows = [_as_dict(e) for e in entries]
    rows.sort(key=lambda r: r['seq'])
    seqs = [r['seq'] for r in rows]

    # 乱序检测（传入顺序与 seq 升序不一致）。
    raw_order = [_as_dict(e)['seq'] for e in entries]
    if raw_order != sorted(raw_order):
        issues.append({'type': 'order', 'detail': '凭据未按 seq 升序排列，存在乱序'})

    # 缺条/空号检测：从 0 起必须连续。
    expected = list(range(0, seqs[-1] + 1))
    missing = sorted(set(expected) - set(seqs))
    if missing:
        preview = ', '.join(map(str, missing[:10]))
        more = '…' if len(missing) > 10 else ''
        issues.append({'type': 'gap', 'detail': f'缺少 seq {preview}{more}，共 {len(missing)} 条'})
    dup = sorted({s for s in seqs if seqs.count(s) > 1})
    if dup:
        issues.append({'type': 'gap', 'detail': f'seq 重复：{dup}'})

    # 可信起点检测。
    first = rows[0]
    want_genesis = expect_genesis_hash or genesis_hash()
    if first['seq'] != GENESIS_SEQ:
        issues.append({'type': 'genesis', 'detail': f'缺少可信起点 genesis（seq=0），首条为 seq={first["seq"]}'})
    elif first['entry_hash'] != want_genesis:
        issues.append({'type': 'genesis', 'detail': 'genesis 凭据内容与可信起点不符'})

    # 逐条哈希与链接检测（篡改）。
    prev_hash = '0' * 64
    by_seq = {r['seq']: r for r in rows}
    for seq in seqs:
        r = by_seq[seq]
        recalc = entry_hash(r['seq'], r['event'], r['actor'], r['payload'], r['prev_hash'], r['at'])
        if recalc != r['entry_hash']:
            issues.append({'type': 'tamper', 'detail': f'seq={seq} 自哈希不一致，内容被篡改'})
        if r['prev_hash'] != prev_hash:
            issues.append({'type': 'tamper', 'detail': f'seq={seq} prev_hash 断链，前序凭据被删改'})
        prev_hash = r['entry_hash']

    # 整段尾部被删：封存/期望终点与实际末条不一致。
    head_seq = seqs[-1]
    if expected_tail is not None and head_seq < expected_tail:
        issues.append({'type': 'truncated',
                       'detail': f'尾部被删：应到 seq={expected_tail}，实际仅到 seq={head_seq}'})

    return {'ok': not issues, 'issues': issues, 'count': len(rows),
            'head_seq': head_seq, 'tail_hash': prev_hash}


def _as_dict(e):
    if isinstance(e, dict):
        return e
    return {'seq': e.seq, 'event': e.event, 'actor': e.actor, 'payload': e.payload,
            'prev_hash': e.prev_hash, 'entry_hash': e.entry_hash, 'at': e.at}


def verify_live(db, expected_tail=None):
    entries = list(db.scalars(select(Credential).order_by(Credential.seq.asc())))
    return _check(entries, expected_tail=expected_tail)


def verify_seal_rows(db, seal):
    entries = list(db.scalars(
        select(SealEntry).where(SealEntry.seal_id == seal.id).order_by(SealEntry.seq.asc())
    ))
    return _check(entries, expected_tail=seal.up_to_seq)


def verify_bundle(bundle):
    """离线核验封存包；只使用包内数据，可由独立脚本执行。"""
    if not isinstance(bundle, dict) or bundle.get('format') != 'credential-seal/v1':
        return {'ok': False, 'issues': [{'type': 'tamper', 'detail': '封存包格式无法识别'}],
                'count': 0, 'head_seq': None, 'tail_hash': None, 'seal_hash_ok': False}
    seal = bundle.get('seal', {})
    entries = bundle.get('entries', [])
    result = _check(entries, expected_tail=seal.get('up_to_seq'))

    seal_hash_ok = False
    if seal.get('entry_count') is not None and seal.get('entry_count') != len(entries):
        result['issues'].append({'type': 'gap',
                                 'detail': f"封存声明 {seal.get('entry_count')} 条，实际 {len(entries)} 条"})
    actual = _bundle_seal_hash(bundle)
    seal_hash_ok = (actual == seal.get('seal_hash'))
    if not seal_hash_ok:
        result['issues'].append({'type': 'tamper',
                                 'detail': f"封存总哈希不一致：声明 {str(seal.get('seal_hash'))[:16]}…，实算 {actual[:16]}…"})
    result['seal_hash_ok'] = seal_hash_ok
    result['ok'] = result['ok'] and seal_hash_ok
    result['seal'] = seal
    return result


def _bundle_seal_hash(bundle):
    import hashlib
    from src.utils.serialization import canonical_json
    seal = bundle['seal']
    digest = hashlib.sha256()
    for e in sorted(bundle['entries'], key=lambda r: r['seq']):
        digest.update(canonical_json({
            'seq': e['seq'], 'event': e['event'], 'actor': e['actor'], 'payload': e['payload'],
            'prev_hash': e['prev_hash'], 'entry_hash': e['entry_hash'], 'at': e['at'],
        }).encode('utf-8'))
    digest.update(canonical_json({
        'seal_code': seal['seal_code'], 'up_to_seq': seal['up_to_seq'],
        'entry_count': seal['up_to_seq'] + 1,
    }).encode('utf-8'))
    return digest.hexdigest()
