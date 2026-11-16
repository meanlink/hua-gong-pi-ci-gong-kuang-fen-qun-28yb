from sqlalchemy import String, Double, JSON, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from src.config.database import Base


class Seal(Base):
    """负责人对截至某条凭据的封存；可中断恢复，重试沿用同一封存内容。"""
    __tablename__ = 'seals'
    id: Mapped[int] = mapped_column(primary_key=True)
    seal_code: Mapped[str] = mapped_column(String(40), unique=True, index=True)
    up_to_seq: Mapped[int]
    entry_count: Mapped[int] = mapped_column(default=0)
    seal_hash: Mapped[str] = mapped_column(String(64), default='')
    status: Mapped[str] = mapped_column(String(20), default='processing')  # processing/completed/failed
    idem_key: Mapped[str | None] = mapped_column(String(200), nullable=True, index=True)
    created_by: Mapped[str] = mapped_column(String(150))
    created_at: Mapped[float] = mapped_column(Double)
    finished_at: Mapped[float | None] = mapped_column(Double, nullable=True)
    last_seq: Mapped[int] = mapped_column(default=-1)
    error: Mapped[str] = mapped_column(String(1000), default='')


class SealEntry(Base):
    """封存时逐条另存的凭据快照，与在线库隔离，作为离线核验的独立依据。"""
    __tablename__ = 'seal_entries'
    __table_args__ = (UniqueConstraint('seal_id', 'seq', name='uq_seal_entry_seq'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    seal_id: Mapped[int] = mapped_column(index=True)
    seq: Mapped[int]
    event: Mapped[str] = mapped_column(String(80))
    actor: Mapped[str] = mapped_column(String(150))
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64))
    at: Mapped[float] = mapped_column(Double)
