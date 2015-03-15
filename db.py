import llog

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
    Index("address", Peer.address)

    d.Peer = Peer

    return d

class Db():
    def __init__(self, url, schema=None):
        self.url = url
        self.Session = None

        self.engine = None

        self.schema = schema

        self.sqlite_lock = None

        self._init_db()

    @property
    def schema(self):
        return self._schema

    @schema.setter
    def schema(self, value):
        self._schema = value
        self.schema_setcmd = "set search_path={}".format(self._schema)

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
        log.info("Creating engine.")
        self.engine = create_engine(self.url, echo=False)

        log.info("Configuring engine...")
        if self.url.startswith("sqlite:"):
            self.sqlite_lock = threading.Lock()
        else:
            if self._schema:
                def set_search_path(conn, proxy):
                    if log.isEnabledFor(logging.INFO):
                        log.info("Setting search path [{}]."\
                            .format(self.schema))
                    conn.cursor().execute(self.schema_setcmd)
                    conn.commit()

                event.listen(self.engine.pool, "connect", set_search_path)

        self.Session = sessionmaker(bind=self.engine)

        # This next line uses a connection, so make sure all event handlers are
        # connected and such before we run this line.
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
