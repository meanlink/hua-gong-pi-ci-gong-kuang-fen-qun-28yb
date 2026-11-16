from sqlalchemy import String, Double, JSON, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from src.config.database import Base


class Credential(Base):
    """追加式哈希链凭据。seq 全库唯一且连续，prev_hash/entry_hash 构成防篡改链。"""
    __tablename__ = 'credentials'
    __table_args__ = (UniqueConstraint('seq', name='uq_credentials_seq'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    seq: Mapped[int]
    event: Mapped[str] = mapped_column(String(80))
    actor: Mapped[str] = mapped_column(String(150))
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64), index=True)
    at: Mapped[float] = mapped_column(Double)
