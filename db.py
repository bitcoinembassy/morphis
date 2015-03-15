import threading
from contextlib import contextmanager

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine, text
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.orm import sessionmaker
from sqlalchemy.types import LargeBinary, Boolean, DateTime

Base = declarative_base()

class Peer(Base):
    __tablename__ = "Peer"
    
    id = Column(Integer, primary_key=True)
    name = Column(String(48), nullable=True)

    node_id = Column(LargeBinary, nullable=True)
    pubkey = Column(LargeBinary, nullable=True)

    distance = Column(Integer, nullable=True)
    direction = Column(Integer, nullable=True)
    
    address = Column(String, nullable=True)

    connected = Column(Boolean, nullable=False)

    last_connect_attempt = Column(DateTime, nullable=True)

class Db():
    def __init__(self, url):
        self.url = url
        self.Session = None

        self.engine = None

        self.sqlite_lock = None

        self._init_db()

    def get_engine(self):
        return self.engine

    @contextmanager
    def open_session(self):
        if self.sqlite_lock:
            self.sqlite_lock.acquire()

        try:
            session = self.Session()
            try:
                yield session
                session.rollback()
            except:
                try:
                    session.rollback()
                except:
                    pass

                raise
            finally:
                session.close()
        finally:
            if self.sqlite_lock:
                self.sqlite_lock.release()

    def lock_table(self, sess, tableobj):
        if self.sqlite_lock:
            return

        t = text("LOCK \"{}\" IN SHARE ROW EXCLUSIVE MODE"\
            .format(tableobj.__table__.name))
        sess.connection().execute(t)

    def _init_db(self):
        self.engine = create_engine(self.url, echo=False)
        Base.metadata.create_all(self.engine)

        self.Session = sessionmaker(bind=self.engine)

        if self.url.startswith("sqlite:"):
            self.sqlite_lock = threading.Lock()
