from src.config.database import Base, engine, Session
from src import models
from src.services.credentials import ensure_genesis
def migrate():
    Base.metadata.create_all(engine)
    with Session() as db:
        ensure_genesis(db)
        db.commit()
if __name__=='__main__':migrate()
