from sqlalchemy import String, Double, Text
from sqlalchemy.orm import Mapped, mapped_column
from src.config.database import Base


class IdempotencyRecord(Base):
    """请求幂等记录：同一 Idempotency-Key 的重试只回放首次结果，不重复变更或记账。"""
    __tablename__ = 'idempotency_records'
    id: Mapped[int] = mapped_column(primary_key=True)
    key: Mapped[str] = mapped_column(String(200), unique=True, index=True)
    path: Mapped[str] = mapped_column(String(200))
    status_code: Mapped[int | None] = mapped_column(nullable=True)
    response_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[float] = mapped_column(Double)
    completed_at: Mapped[float | None] = mapped_column(Double, nullable=True)
