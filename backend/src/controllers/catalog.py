from fastapi import APIRouter, Depends
from sqlalchemy import select, func
from src.config.database import get_db
from src.middlewares.auth import current_user
from src.models import Dataset, Job, Report, Audit, Credential
from src.services.business import metadata
from src.services.credentials import genesis_hash, GENESIS_SEQ
router=APIRouter()
@router.get('/meta')
def meta():return metadata()
@router.get('/overview')
def overview(db=Depends(get_db),user=Depends(current_user)):
    return {'datasets':db.scalar(select(func.count()).select_from(Dataset)), 'records':sum(len(d.records) for d in db.scalars(select(Dataset))), 'jobs':db.scalar(select(func.count()).select_from(Job)), 'approved':db.scalar(select(func.count()).select_from(Job).where(Job.approved==True)), 'reports':db.scalar(select(func.count()).select_from(Report)), 'credentials':db.scalar(select(func.count()).select_from(Credential))}
@router.get('/audits')
def audits(db=Depends(get_db),user=Depends(current_user)):
    """旧审计日志：保留可查，但不属于哈希链，不作为防篡改依据。"""
    rows=[{'id':a.id,'actor':a.actor,'action':a.action,'detail':a.detail,'at':a.at}
          for a in db.scalars(select(Audit).order_by(Audit.id.desc()).limit(50))]
    return {
        'legacy_entries': rows,
        'trust': {
            'mode': 'hash-chain',
            'genesis_seq': GENESIS_SEQ,
            'genesis_hash': genesis_hash(),
            'note': '以下为旧版操作日志，可被删改且无链式保护；防篡改核验请使用 /credibility 凭据链。',
        },
    }
