"""凭据封存服务。

- 封存截至某条 seq 的凭据，逐条另存到 seal_entries，与在线凭据表隔离。
- 封存范围在创建时固定（up_to_seq），封存途中新产生的凭据不会混入。
- 分批在小事务内快照，中断后可从 last_seq 恢复；重试沿用同一封存内容。
- 完成后计算封存总哈希，导出的独立文件以另存快照为准，不依赖在线库。
"""
import hashlib
import secrets
import time
from fastapi import HTTPException
from sqlalchemy import select
from src.models import Credential, Seal, SealEntry
from src.services.credentials import entry_hash, ensure_genesis, max_seq
from src.utils.serialization import canonical_json

BATCH = 200


def _seal_code():
    return 'SEAL-' + time.strftime('%Y%m%d') + '-' + secrets.token_hex(4)


def get_seal(db, seal_id=None, seal_code=None):
    if seal_id is not None:
        return db.get(Seal, seal_id)
    return db.scalar(select(Seal).where(Seal.seal_code == seal_code))


def create_seal(db, actor, up_to_seq=None, idem_key=None):
    """创建封存；相同 idem_key 的重试返回原封存，不产生第二份。"""
    if idem_key:
        existing = db.scalar(select(Seal).where(Seal.idem_key == idem_key))
        if existing:
            return existing
    ensure_genesis(db)
    head = max_seq(db)
    if up_to_seq is None:
        up_to_seq = head
    if up_to_seq < 0 or up_to_seq > head:
        raise HTTPException(422, f'封存终点须在 0~{head} 之间')
    seal = Seal(
        seal_code=_seal_code(), up_to_seq=up_to_seq, status='processing',
        idem_key=idem_key, created_by=actor, created_at=time.time(), last_seq=-1,
    )
    db.add(seal)
    db.flush()
    return seal


def resume_seal(db, seal):
    """把封存推进到完成；可重复调用，已完成则原样返回。"""
    if seal.status == 'completed':
        return seal
    seal.status = 'processing'
    try:
        while seal.last_seq < seal.up_to_seq:
            start = seal.last_seq + 1
            end = min(start + BATCH - 1, seal.up_to_seq)
            rows = list(db.scalars(
                select(Credential).where(Credential.seq >= start, Credential.seq <= end)
                .order_by(Credential.seq.asc()).with_for_update()
            ))
            got = [r.seq for r in rows]
            expect = list(range(start, end + 1))
            if got != expect:
                raise RuntimeError(f'凭据缺条：期望 {expect[0]}~{expect[-1]}，实得 {got}')
            for r in rows:
                db.add(SealEntry(
                    seal_id=seal.id, seq=r.seq, event=r.event, actor=r.actor, payload=r.payload,
                    prev_hash=r.prev_hash, entry_hash=r.entry_hash, at=r.at,
                ))
            seal.last_seq = end
            db.commit()  # 每批独立提交，中断后从 last_seq 继续，不重复快照。
        seal.entry_count = seal.up_to_seq + 1
        seal.seal_hash = compute_seal_hash(db, seal)
        seal.status = 'completed'
        seal.finished_at = time.time()
        seal.error = ''
        db.commit()
    except Exception as exc:
        db.rollback()
        seal = db.get(Seal, seal.id)
        seal.status = 'failed'
        seal.error = str(exc)[:990]
        db.commit()
    return seal


def compute_seal_hash(db, seal):
    """对另存的快照按 seq 顺序聚合哈希，任何删改/缺条/乱序都会改变结果。"""
    digest = hashlib.sha256()
    entries = db.scalars(
        select(SealEntry).where(SealEntry.seal_id == seal.id).order_by(SealEntry.seq.asc())
    )
    for e in entries:
        digest.update(canonical_json({
            'seq': e.seq, 'event': e.event, 'actor': e.actor, 'payload': e.payload,
            'prev_hash': e.prev_hash, 'entry_hash': e.entry_hash, 'at': e.at,
        }).encode('utf-8'))
    digest.update(canonical_json({
        'seal_code': seal.seal_code, 'up_to_seq': seal.up_to_seq,
        'entry_count': seal.up_to_seq + 1,
    }).encode('utf-8'))
    return digest.hexdigest()


def snapshot_entries(db, seal):
    return [entry_to_dict(e) for e in db.scalars(
        select(SealEntry).where(SealEntry.seal_id == seal.id).order_by(SealEntry.seq.asc())
    )]


def entry_to_dict(e):
    return {
        'seq': e.seq, 'event': e.event, 'actor': e.actor, 'payload': e.payload,
        'prev_hash': e.prev_hash, 'entry_hash': e.entry_hash, 'at': e.at,
    }


def export_bundle(db, seal):
    """生成自描述封存包：离线核验只依赖该文件本身。"""
    if seal.status != 'completed':
        raise HTTPException(409, '封存尚未完成，无法导出')
    return {
        'format': 'credential-seal/v1',
        'seal': {
            'seal_code': seal.seal_code,
            'up_to_seq': seal.up_to_seq,
            'entry_count': seal.entry_count,
            'seal_hash': seal.seal_hash,
            'created_by': seal.created_by,
            'created_at': seal.created_at,
            'finished_at': seal.finished_at,
        },
        'entries': snapshot_entries(db, seal),
    }
