import llog

import asyncio
import threading
import logging
from contextlib import contextmanager

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.schema import Index
from sqlalchemy import create_engine, text, event, MetaData
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import Pool
from sqlalchemy.types import LargeBinary, Boolean, DateTime

log = logging.getLogger(__name__)

Base = declarative_base()
Peer = None

def _init_daos(Base, d):
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

    Index("node_id", Peer.node_id)
    Index("distance", Peer.distance)
    Index("connected", Peer.connected)
    Index("connected_distance", Peer.connected, Peer.distance)
    Index("address", Peer.address)

    d.Peer = Peer

    return d

class Db():
    def __init__(self, loop, url, schema=None):
        self.loop = loop
        self.url = url
        self.Session = None

        self.engine = None

        self.schema = schema

        self.sqlite_lock = None

        self.pool_size = 10

    @property
    def schema(self):
        return self._schema

    @schema.setter
    def schema(self, value):
        self._schema = value
        self._schema_setcmd = "set search_path={}".format(self._schema)

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

    def init_engine(self):
        is_sqlite = self.url.startswith("sqlite:")

        log.info("Creating engine.")
        if is_sqlite:
            self.engine = create_engine(self.url, echo=False)
        else:
            self.engine = create_engine(\
                self.url, echo=False,
                pool_size=self.pool_size, max_overflow=0)

        log.info("Configuring engine...")
        if is_sqlite:
            self.sqlite_lock = threading.Lock()
        else:
            if self.schema:
                event.listen(\
                    self.engine.pool, "connect", self._set_search_path)

        self.Session = sessionmaker(bind=self.engine)

    def _set_search_path(self, conn, proxy):
        if log.isEnabledFor(logging.INFO):
            log.info("Setting search path [{}].".format(self.schema))
        conn.cursor().execute(self._schema_setcmd)
        conn.commit()

    @asyncio.coroutine
    def create_all(self):
        yield from self.loop.run_in_executor(None, self._create_all)

    def _create_all(self):
        log.info("Checking/creating schema.")
        if self._schema:
            tmp_Base = declarative_base()
            d = _init_daos(tmp_Base, DObject())
            for t in tmp_Base.metadata.tables.values():
                t.schema = self.schema

            try:
                tmp_Base.metadata.create_all(self.engine)
            except ProgrammingError:
                with self.open_session() as sess:
                    t = text("CREATE SCHEMA {}".format(self.schema))
                    sess.connection().execute(t)
                    sess.commit()

                tmp_Base.metadata.create_all(self.engine)
        else:
            Base.metadata.create_all(self.engine)

class DObject(object):
    pass

if Peer is None:
    d = _init_daos(Base, DObject())

    Peer = d.Peer
