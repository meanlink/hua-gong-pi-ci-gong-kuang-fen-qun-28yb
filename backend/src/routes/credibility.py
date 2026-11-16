from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Header
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import select
import json
from src.config.database import Session, get_db
from src.middlewares.auth import current_user, admin_only
from src.models import Credential, Seal
from src.services import credentials as cred_service, seals as seal_service, verification

router = APIRouter(prefix='/credibility')


class SealInput(BaseModel):
    up_to_seq: int | None = Field(default=None, ge=0)


def seal_dict(s):
    return {k: getattr(s, k) for k in ['id', 'seal_code', 'up_to_seq', 'entry_count', 'seal_hash',
                                       'status', 'created_by', 'created_at', 'finished_at',
                                       'last_seq', 'error']}


@router.get('/anchor')
def anchor(db=Depends(get_db), u=Depends(current_user)):
    """可信起点：固定 genesis 内容与自哈希，供外部独立比对。"""
    g = cred_service.ensure_genesis(db)
    db.commit()
    return {
        'genesis_seq': g.seq, 'event': g.event, 'actor': g.actor, 'payload': g.payload,
        'at': g.at, 'prev_hash': g.prev_hash, 'entry_hash': g.entry_hash,
        'expected_hash': cred_service.genesis_hash(),
        'legacy_audit_note': '旧 audits 表为操作日志，不属于哈希链；链上凭据以 genesis(seq=0) 为唯一可信起点。',
    }


@router.get('/credentials')
def list_credentials(limit: int = 200, db=Depends(get_db), u=Depends(current_user)):
    rows = db.scalars(select(Credential).order_by(Credential.seq.desc()).limit(min(max(limit, 1), 1000)))
    return [{'seq': c.seq, 'event': c.event, 'actor': c.actor, 'payload': c.payload,
             'prev_hash': c.prev_hash, 'entry_hash': c.entry_hash, 'at': c.at} for c in rows]


@router.get('/verify')
def verify_live(db=Depends(get_db), u=Depends(current_user)):
    return verification.verify_live(db)


@router.post('/seals', status_code=201)
def create_seal(body: SealInput, db=Depends(get_db), u=Depends(admin_only),
                idempotency_key: str | None = Header(default=None, alias='idempotency-key')):
    idem = (idempotency_key or '').strip() or None
    seal = seal_service.create_seal(db, u.email, body.up_to_seq, idem)
    cred_service.append(db, 'seal.started', u.email, {
        'seal_code': seal.seal_code, 'up_to_seq': seal.up_to_seq,
    })
    db.commit()
    seal = seal_service.resume_seal(db, seal)
    if seal.status == 'completed':
        with Session() as db2:
            latest = seal_service.get_seal(db2, seal_id=seal.id)
            cred_service.append(db2, 'seal.completed', u.email, {
                'seal_code': latest.seal_code, 'up_to_seq': latest.up_to_seq,
                'entry_count': latest.entry_count, 'seal_hash': latest.seal_hash,
            })
            db2.commit()
    return seal_dict(seal_service.get_seal(db, seal_id=seal.id))


@router.get('/seals')
def list_seals(db=Depends(get_db), u=Depends(current_user)):
    return [seal_dict(s) for s in db.scalars(select(Seal).order_by(Seal.id.desc()))]


@router.get('/seals/{seal_id}')
def get_seal(seal_id: int, db=Depends(get_db), u=Depends(current_user)):
    s = seal_service.get_seal(db, seal_id=seal_id)
    if not s:
        raise HTTPException(404, '封存不存在')
    return seal_dict(s)


@router.post('/seals/{seal_id}/resume')
def resume_seal(seal_id: int, db=Depends(get_db), u=Depends(admin_only)):
    s = seal_service.get_seal(db, seal_id=seal_id)
    if not s:
        raise HTTPException(404, '封存不存在')
    before = s.status
    s = seal_service.resume_seal(db, s)
    if before != 'completed' and s.status == 'completed':
        with Session() as db2:
            latest = seal_service.get_seal(db2, seal_id=s.id)
            cred_service.append(db2, 'seal.completed', u.email, {
                'seal_code': latest.seal_code, 'up_to_seq': latest.up_to_seq,
                'entry_count': latest.entry_count, 'seal_hash': latest.seal_hash,
            })
            db2.commit()
    return seal_dict(seal_service.get_seal(db, seal_id=s.id))


@router.get('/seals/{seal_id}/export')
def export_seal(seal_id: int, db=Depends(get_db), u=Depends(current_user)):
    s = seal_service.get_seal(db, seal_id=seal_id)
    if not s:
        raise HTTPException(404, '封存不存在')
    bundle = seal_service.export_bundle(db, s)
    payload = json.dumps(bundle, ensure_ascii=False, allow_nan=False, indent=2).encode('utf-8')
    return Response(
        content=payload,
        media_type='application/json; charset=utf-8',
        headers={'Content-Disposition': f'attachment; filename="{s.seal_code}.seal.json"'},
    )


@router.post('/seals/verify-upload')
async def verify_upload(file: UploadFile = File(...), u=Depends(current_user)):
    raw = await file.read()
    if len(raw) > 20 * 1024 * 1024:
        raise HTTPException(422, '封存文件过大（上限 20MB）')
    try:
        bundle = json.loads(raw.decode('utf-8'))
    except Exception:
        raise HTTPException(422, '无法解析封存 JSON')
    result = verification.verify_bundle(bundle)
    return result
