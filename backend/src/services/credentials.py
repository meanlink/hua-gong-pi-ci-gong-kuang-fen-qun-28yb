"""连续哈希链凭据服务。

设计要点：
- 全局唯一连续 seq，由数据库行锁串行分配；并发操作仍有唯一顺序。
- 每条凭据含前一条 entry_hash（prev_hash），自哈希覆盖 seq/event/actor/payload/prev_hash/at。
- 凭据与业务变更在同一事务内写入：业务失败则整体回滚，不占用 seq（不留空号）。
- 第 0 条为可信起点 genesis，内容固定并在迁移/启动时幂等建立。
"""
import hashlib
import time
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from src.models import Credential
from src.utils.serialization import canonical_json
GENESIS_SEQ = 0
GENESIS_EVENT = 'chain.genesis'
GENESIS_ACTOR = 'system'
GENESIS_PAYLOAD = {
    'purpose': '工艺复查连续凭据链可信起点',
    'scope': ['dataset.intake', 'job.lifecycle', 'job.approval', 'report.archive', 'seal.lifecycle'],
    'version': 1,
}
GENESIS_AT = 1763000000.0


def entry_hash(seq, event, actor, payload, prev_hash, at):
    material = canonical_json({
        'seq': seq, 'event': event, 'actor': actor, 'payload': payload,
        'prev_hash': prev_hash, 'at': at,
    })
    return hashlib.sha256(material.encode('utf-8')).hexdigest()


def genesis_hash():
    return entry_hash(GENESIS_SEQ, GENESIS_EVENT, GENESIS_ACTOR, GENESIS_PAYLOAD, '0' * 64, GENESIS_AT)


def ensure_genesis(db):
    """幂等建立可信起点。返回 genesis 凭据；已存在则直接返回。"""
    existing = db.scalar(select(Credential).where(Credential.seq == GENESIS_SEQ))
    if existing:
        return existing
    row = Credential(
        seq=GENESIS_SEQ, event=GENESIS_EVENT, actor=GENESIS_ACTOR, payload=GENESIS_PAYLOAD,
        prev_hash='0' * 64, entry_hash=genesis_hash(), at=GENESIS_AT,
    )
    db.add(row)
    try:
        db.flush()
        return row
    except IntegrityError:
        # 并发下另一个事务已建立 genesis。
        db.rollback()
        return db.scalar(select(Credential).where(Credential.seq == GENESIS_SEQ))


def _lock_tail(db):
    """取链尾并加行锁，串行化并发序号分配（MySQL 为 SELECT ... FOR UPDATE）。"""
    tail = db.scalar(select(Credential).order_by(Credential.seq.desc()).limit(1).with_for_update())
    if tail is None:
        tail = ensure_genesis(db)
    return tail


def append(db, event, actor, payload=None):
    """在当前事务内追加一条凭据；调用方随业务变更一起 commit 或一起 rollback。

    行锁 FOR UPDATE（MySQL/InnoDB）或库级写锁（SQLite）串行化并发序号分配，
    因此 seq 全库唯一且连续；极端冲突时直接抛错，由外层整体回滚，不吞错、不留空号。
    """
    payload = payload or {}
    tail = _lock_tail(db)
    seq = tail.seq + 1
    at = time.time()
    prev_hash = tail.entry_hash
    h = entry_hash(seq, event, actor, payload, prev_hash, at)
    row = Credential(seq=seq, event=event, actor=actor, payload=payload,
                     prev_hash=prev_hash, entry_hash=h, at=at)
    db.add(row)
    db.flush()
    return row


def all_entries(db):
    return list(db.scalars(select(Credential).order_by(Credential.seq.asc())))


def max_seq(db):
    tail = db.scalar(select(Credential).order_by(Credential.seq.desc()).limit(1))
    return tail.seq if tail else GENESIS_SEQ
