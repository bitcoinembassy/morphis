# Copyright (c) 2014-2015  Sam Maloney.
# License: GPL v2.

import llog

import asyncio
import threading
import logging
from contextlib import contextmanager

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.schema import Index
from sqlalchemy import create_engine, text, event, MetaData, func, Table,\
    Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.exc import ProgrammingError, OperationalError
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.pool import Pool
from sqlalchemy.types import LargeBinary, Boolean, DateTime

log = logging.getLogger(__name__)

Base = declarative_base()

Peer = None
DataBlock = None
NodeState = None
DmailAddress = None
DmailKey = None
DmailMessage = None
DmailPart = None
DmailTag = None

def _init_daos(Base, d):
    # If I recall correctly, this abomination is purely for PostgreSQL mode,
    # and only for the create schema. It is because while setting the
    # search_path works for all usage, there is the one exception that the
    # create schema code of SQLAlchemy runs before that gets set or something
    # (I think that was it) and the schema won't be created in separate schemas
    # as desired. Hopefully we can get SQLAlchemy fixed and then this
    # complication removed.
    class Peer(Base):
        __tablename__ = "peer"

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

    class DataBlock(Base):
        __tablename__ = "datablock"

        id = Column(Integer, primary_key=True)
        data_id = Column(LargeBinary, nullable=False)
        distance = Column(LargeBinary, nullable=False)
        original_size = Column(Integer, nullable=False)
        insert_timestamp = Column(DateTime, nullable=False)
        last_access = Column(DateTime, nullable=True)
        version = Column(String, nullable=True) # str for sqlite bigint :(.
        signature = Column(LargeBinary, nullable=True)
        epubkey = Column(LargeBinary, nullable=True)
        pubkeylen = Column(Integer, nullable=True)
        target_key = Column(LargeBinary, nullable=True)

    Index("data_id", DataBlock.data_id)
    Index("datablock__distance", DataBlock.distance.desc())

    d.DataBlock = DataBlock

    class NodeState(Base):
        __tablename__ = "nodestate"

        key = Column(String(64), primary_key=True)
        value = Column(String(128), nullable=True)

    d.NodeState = NodeState

    class DmailKey(Base):
        __tablename__ = "dmailkey"

        id = Column(Integer, primary_key=True)
        parent_id = Column(Integer, ForeignKey("dmailaddress.id"))
        x = Column(LargeBinary, nullable=False)
        target_key = Column(LargeBinary, nullable=False)
        difficulty = Column(Integer, nullable=False)

    d.DmailKey = DmailKey

    class DmailAddress(Base):
        __tablename__ = "dmailaddress"

        id = Column(Integer, primary_key=True)
        site_key = Column(LargeBinary, nullable=False)
        site_privatekey = Column(LargeBinary, nullable=True)
        keys = relationship(DmailKey)

    Index("dmailaddress__site_key", DmailAddress.site_key)

    d.DmailAddress = DmailAddress

    dmail_message__dmail_tag = Table(\
        "dmail_message__dmail_tag",\
        Base.metadata,\
        Column("dmail_message_id", Integer, ForeignKey("dmailmessage.id")),\
        Column("tag_id", Integer, ForeignKey("dmailtag.id")))

    class DmailTag(Base):
        __tablename__ = "dmailtag"

        id = Column(Integer, primary_key=True)
        name = Column(String, nullable=False)

    Index("dmailtag__name", DmailTag.name)

    d.DmailTag = DmailTag

    class DmailPart(Base):
        __tablename__ = "dmailpart"

        id = Column(Integer, primary_key=True)
        dmail_message_id = Column(Integer, ForeignKey("dmailmessage.id"))
        mime_type = Column(String, nullable=True)
        data = Column(LargeBinary, nullable=False)

    d.DmailPart = DmailPart

    class DmailMessage(Base):
        __tablename__ = "dmailmessage"

        id = Column(Integer, primary_key=True)
        dmail_address_id = Column(Integer, ForeignKey("dmailaddress.id"))
        data_key = Column(LargeBinary, nullable=False)
        sender_dmail_key = Column(LargeBinary, nullable=True)
        sender_valid = Column(Boolean, nullable=True)
        subject = Column(String, nullable=False)
        date = Column(DateTime, nullable=False)
        read = Column(Boolean, nullable=False)
        hidden = Column(Boolean, nullable=False)
        tags = relationship(DmailTag, secondary=dmail_message__dmail_tag)
        address = relationship(DmailAddress)
        parts = relationship(DmailPart)

    Index("dmailmessage__data_key", DmailMessage.data_key)

    d.DmailMessage = DmailMessage

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
    def open_session(self, read_only=False):
        if self.sqlite_lock and not read_only:
            self.sqlite_lock.acquire()

        try:
            session = self.Session()
            try:
                yield session
            finally:
                try:
                    session.close()
                except TypeError:
                    log.exception("SqlAlchemy crashed; workaround engaged;"\
                        " Session leaked! Upgrade to 1.0.8 to prevent this!")
        except:
            log.exception("Db session contextmanager.")
            raise
        finally:
            if self.sqlite_lock and not read_only:
                self.sqlite_lock.release()

    def lock_table(self, sess, tableobj):
        if self.sqlite_lock:
            return

        st = "LOCK \"{}\" IN SHARE ROW EXCLUSIVE MODE"\
            .format(tableobj.__table__.name)
        sess.execute(st)

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
    def ensure_schema(self):
        yield from self.loop.run_in_executor(None, self._ensure_schema)

    def _ensure_schema(self):
        log.info("Checking schema.")

        new_db = False

        with self.open_session(True) as sess:
            q = sess.query(NodeState)\
                .filter(NodeState.key == "db_version")

            try:
                r = q.first()
            except OperationalError:
                new_db = True

        if new_db:
            log.info("Database schema is missing, creating.")
            self._create_schema()

            with self.open_session() as sess:
                ns = NodeState()
                ns.key = "db_version"
                ns.value = "1"
                sess.add(ns)
                sess.commit()
                return

        if r:
            version = int(r.value)
        else:
            # This is the schema before we started tracking version in db.
            version = 1

        if log.isEnabledFor(logging.INFO):
            log.info("Existing schema detected (version=[{}]).".format(version))

#        if version == 1:
#            log.info("Upgrading database schema from version 1 to 2.")
#            _upgrade_1_to_2(self)

    def _create_schema(self):
        log.info("Creating schema.")

        if self._schema:
            tmp_Base = declarative_base()
            d = _init_daos(tmp_Base, DObject())
            for t in tmp_Base.metadata.tables.values():
                t.schema = self.schema

            try:
                tmp_Base.metadata.create_all(self.engine)
            except ProgrammingError:
                with self.open_session() as sess:
                    st = "CREATE SCHEMA {}".format(self.schema)
                    sess.execute(st)
                    sess.commit()

                tmp_Base.metadata.create_all(self.engine)
        else:
            Base.metadata.create_all(self.engine)

class DObject(object):
    pass

if Peer is None:
    d = _init_daos(Base, DObject())

    Peer = d.Peer
    DataBlock = d.DataBlock
    NodeState = d.NodeState

    # Maalstroom Dmail Client.
    DmailAddress = d.DmailAddress
    DmailKey = d.DmailKey
    DmailMessage = d.DmailMessage
    DmailPart = d.DmailPart
    DmailTag = d.DmailTag

def _upgrade_1_to_2(db):
    pass
