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
    Column, ForeignKey, Integer, String, DateTime, TypeDecorator
from sqlalchemy.exc import ProgrammingError, OperationalError
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.pool import Pool
from sqlalchemy.types import LargeBinary, Boolean, DateTime

import consts
import mutil

log = logging.getLogger(__name__)

LATEST_SCHEMA_VERSION = 4

Base = declarative_base()

Peer = None
DataBlock = None
NodeState = None
DmailAddress = None
DmailKey = None
DmailMessage = None
DmailPart = None
DmailTag = None

class UtcDateTime(TypeDecorator):
    impl = DateTime

    def process_result_value(self, value, dialect):
        return\
            None if value is None else value.replace(tzinfo=mutil.UTC_TZINFO)

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

        last_connect_attempt = Column(UtcDateTime, nullable=True)

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
        insert_timestamp = Column(UtcDateTime, nullable=False)
        last_access = Column(UtcDateTime, nullable=True)
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
        scan_interval = Column(Integer, nullable=True)
        keys = relationship(DmailKey)
        messages = relationship("DmailMessage")

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
        dmail_key_id = Column(Integer, nullable=True)
        data_key = Column(LargeBinary, nullable=False)
        sender_dmail_key = Column(LargeBinary, nullable=True)
        sender_valid = Column(Boolean, nullable=True)
        destination_dmail_key = Column(LargeBinary, nullable=True)
        destination_significant_bits = Column(Integer, nullable=True)
        subject = Column(String, nullable=False)
        date = Column(UtcDateTime, nullable=False)
        read = Column(Boolean, nullable=False)
        hidden = Column(Boolean, nullable=False)
        deleted = Column(Boolean, nullable=False)
        tags = relationship(DmailTag, secondary=dmail_message__dmail_tag)
        address = relationship(DmailAddress)
        parts = relationship(DmailPart, cascade="all, delete-orphan")

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

        self.is_sqlite = False
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
        read_only = False; #TODO: Need to implement a read-write lock.

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
        except Exception:
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
        self.is_sqlite = self.url.startswith("sqlite:")

        log.info("Creating engine.")
        if self.is_sqlite:
            self.engine = create_engine(self.url, echo=False)
        else:
            self.engine = create_engine(\
                self.url, echo=False,
                pool_size=self.pool_size, max_overflow=0)

        log.info("Configuring engine...")
        if self.is_sqlite:
            self.sqlite_lock = threading.Lock()

            # The following KLUDGE is from SqlAlchemy docs. SqlAlchemy says the
            # pysqlite drivers is broken and decides to 'help' by not honoring
            # your transaction begin statement and to also auto commit even
            # though you told it not to.
            @event.listens_for(self.engine, "connect")
            def do_connect(dbapi_connection, connection_record):
                # Disable pysqlite's emitting of the BEGIN statement entirely.
                # Also stops it from emitting COMMIT before any DDL.
                dbapi_connection.isolation_level = None

            @event.listens_for(self.engine, "begin")
            def do_begin(conn):
                # Emit our own BEGIN.
                conn.execute("BEGIN")
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
                .filter(NodeState.key == consts.NSK_SCHEMA_VERSION)

            try:
                r = q.first()
            except OperationalError:
                new_db = True

        if new_db:
            log.info("Database schema is missing, creating.")
            self._create_schema()

            with self.open_session() as sess:
                ns = NodeState()
                ns.key = consts.NSK_SCHEMA_VERSION
                ns.value = str(LATEST_SCHEMA_VERSION)
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

        # Perform necessary upgrades.
        if version == 1:
            if _test_and_fix_if_really_4(self):
                version = 4
            else:
                _upgrade_1_to_2(self)
                version = 2

        if version == 2:
            _upgrade_2_to_3(self)
            version = 3

        if version == 3:
            _upgrade_3_to_4(self)
            version = LATEST_SCHEMA_VERSION

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

def _update_node_state(sess, version):
    "Caller must call commit."

    q = sess.query(NodeState)\
        .filter(NodeState.key == consts.NSK_SCHEMA_VERSION)

    ns = q.first()

    if not ns:
        ns = NodeState()
        ns.key = consts.NSK_SCHEMA_VERSION
        sess.add(ns)

    ns.value = str(version)

def _test_and_fix_if_really_4(db):
    with db.open_session() as sess:
        q = sess.query(DmailMessage)\
            .filter(DmailMessage.deleted == False)

        try:
            test = q.all()

            _update_node_state(sess, 4)

            sess.commit()

            is_4 = True
        except Exception:
            is_4 = False

        return is_4

def _upgrade_1_to_2(db):
    log.warning("NOTE: Upgrading database schema from version 1 to 2.")

    t_bytea = "BLOB" if db.is_sqlite else "bytea"
    t_integer = "INTEGER" if db.is_sqlite else "integer"

    with db.open_session() as sess:
        st = "ALTER TABLE dmailmessage ADD COLUMN destination_dmail_key "\
                + t_bytea

        sess.execute(st)

        st = "ALTER TABLE dmailmessage ADD COLUMN"\
            " destination_significant_bits "\
                + t_integer

        sess.execute(st)

        _update_node_state(sess, 2)

        sess.commit()

    log.warning("NOTE: Database schema upgraded.")

def _upgrade_2_to_3(db):
    log.warning("NOTE: Upgrading database schema from version 2 to 3.")

    t_integer = "INTEGER" if db.is_sqlite else "integer"

    with db.open_session() as sess:
        st = "ALTER TABLE dmailaddress ADD COLUMN scan_interval "\
            + t_integer

        sess.execute(st)

        _update_node_state(sess, 3)

        sess.commit()

    log.warning("NOTE: Database schema upgraded.")

def _upgrade_3_to_4(db):
    log.warning("NOTE: Upgrading database schema from version 3 to 4.")

    t_integer = "INTEGER" if db.is_sqlite else "integer"

    with db.open_session() as sess:
        st = "ALTER TABLE dmailmessage ADD COLUMN dmail_key_id "\
            + t_integer

        sess.execute(st)

        default = "0" if db.is_sqlite else "false"

        st = "ALTER TABLE dmailmessage ADD COLUMN deleted BOOLEAN not null"\
            + " default " + default

        sess.execute(st)

        _update_node_state(sess, 4)

        sess.commit()

    log.warning("NOTE: Database schema upgraded.")
