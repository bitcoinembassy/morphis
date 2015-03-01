from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.orm import sessionmaker
from sqlalchemy.types import BINARY

Base = declarative_base()

class Peer(Base):
    __tablename__ = "Peer"
    
    id = Column(Integer, primary_key=True)
    name = Column(String(48), nullable=True)

    nodeid = Column(BINARY, nullable=True)
    pubkey = Column(BINARY, nullable=True)
    
    address = Column(String, nullable=True)

class Db():
    def __init__(self, url):
        self.url = url
        self.Session = None

        self._init_db()

    def get_engine(self):
        return self.engine

    def open_session(self):
        return self.Session()

    def _init_db(self):
        self.engine = create_engine(self.url, echo=False)
        Base.metadata.create_all(self.engine)

        self.Session = sessionmaker(bind=self.engine)
