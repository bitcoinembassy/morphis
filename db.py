# Copyright (c) 2014-2015  Sam Maloney.
# License: GPL v2.

import llog

import asyncio
from contextlib import contextmanager
from enum import Enum
import logging
from pkg_resources import parse_version
import threading

from sqlalchemy import __version__ as sqlalchemy__version__
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.schema import Index, UniqueConstraint
from sqlalchemy import create_engine, text, event, MetaData, func, Table,\
    Column, ForeignKey, Integer, String, DateTime, TypeDecorator, update
from sqlalchemy.exc import ProgrammingError, OperationalError
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.pool import Pool
from sqlalchemy.types import LargeBinary, Boolean, DateTime

import consts
import mutil

log = logging.getLogger(__name__)

LATEST_SCHEMA_VERSION = 5

Base = declarative_base()
AddressBook = None
Peer = None
DataBlock = None
NodeState = None
DmailAddress = None
DmailKey = None
DmailMessage = None
DmailPart = None
DmailTag = None

##FIXME: NEW
User = None
DdsPost = None
DdsStamp = None
Synapse = None
SynapseKey = None
Stamp = None
##.

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

    class AddressBook(Base):
        __tablename__ = "addressbook"

        id = Column(Integer, primary_key=True)
        identity_key = Column(LargeBinary, nullable=False)
        name = Column(String, nullable=False)
        last = Column(String, nullable=True)
        first = Column(String, nullable=True)
        user = Column(LargeBinary, nullable=True)

    Index("addressbook_identity_key", AddressBook.last)
    Index("addressbook_name", AddressBook.last)
    Index("addressbook_first", AddressBook.last)
    Index("addressbook_last", AddressBook.last)

    d.AddressBook = AddressBook

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
    Index("datablock__target_key", DataBlock.target_key)

    d.DataBlock = DataBlock

    class Synapse(Base):
        __tablename__ = "synapse"

        id = Column(Integer, primary_key=True)
        data = Column(LargeBinary, nullable=True)
        original_size = Column(Integer, nullable=False)
        insert_timestamp = Column(UtcDateTime, nullable=False)
        last_access = Column(UtcDateTime, nullable=True)
        keys = relationship("SynapseKey", cascade="all, delete-orphan")

        timestamp = Column(UtcDateTime, nullable=False)
        pow_difficulty = Column(Integer, nullable=True)

    d.Synapse = Synapse

    class SynapseKey(Base):
        __tablename__ = "synapsekey"

        data_id = Column(LargeBinary, nullable=False, primary_key=True)
        #FIXME: I don't think distance is used anywhere (although it gets set).
        distance = Column(LargeBinary, nullable=False)
        synapse = relationship(Synapse)
        synapse_id =\
            Column(Integer, ForeignKey("synapse.id"), primary_key=True)
        key_type = Column(Integer, nullable=False, primary_key=True)
        ekey = Column(LargeBinary, nullable=False)
        last_access = Column(UtcDateTime, nullable=True)

        # Logically in Synapse, but instead here for hopefully faster queries.
        timestamp = Column(UtcDateTime, nullable=False)
        pow_difficulty = Column(Integer, nullable=True)

        class KeyType(Enum):
            synapse_key = 1
            synapse_pow = 2
            target_key = 3
            source_key = 4
            signing_key = 5
            stamp_key = 6

    Index("synapsekey__data_id", SynapseKey.data_id)

    d.SynapseKey = SynapseKey

    class Stamp(Base):
        __tablename__ = "stamp"

        id = Column(Integer, primary_key=True)
        stamp_id = Column(LargeBinary, nullable=False)
        signed_id = Column(LargeBinary, nullable=False)
        # str for sqlite bigint :(.
        version = Column(String, nullable=False)
        signing_id = Column(LargeBinary, nullable=False)
        difficulty = Column(Integer, nullable=False)
        revoked = Column(Boolean, nullable=False, default=False)
        first_seen = Column(UtcDateTime, nullable=False)
        data = Column(LargeBinary, nullable=False)
        children = relationship(\
            "Stamp",\
            foreign_keys="Stamp.signing_id",\
            primaryjoin="Stamp.signed_id == Stamp.signing_id",\
            passive_deletes="all")

    Index("stamp__signed_id", Stamp.signed_id)
    Index("stamp__signing_id", Stamp.signing_id)
    UniqueConstraint(Stamp.signed_id, Stamp.version, Stamp.signing_id)

    d.Stamp = Stamp

    class NodeState(Base):
        __tablename__ = "nodestate"

        key = Column(String, primary_key=True)
        value = Column(String, nullable=True)

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

    class User(Base):
        __tablename__ = "user"

        id = Column(Integer, primary_key=True)

    d.User = User

    class DdsPost(Base):
        __tablename__ = "ddspost"

        id = Column(Integer, primary_key=True)
        target_key = Column(\
            LargeBinary, ForeignKey("ddspost.synapse_key"), nullable=True)
        target_key2 = Column(LargeBinary, nullable=True)
        synapse_key = Column(LargeBinary, nullable=True)
        synapse_pow = Column(LargeBinary, nullable=True)
        data_key = Column(LargeBinary, nullable=False)
        data = Column(LargeBinary, nullable=True)
        signing_key = Column(LargeBinary, nullable=True)
        timestamp = Column(UtcDateTime, nullable=False)
        first_seen = Column(UtcDateTime, nullable=False)
        score = Column(Integer, nullable=True) # difficulty.
        children = relationship("DdsPost", cascade="all, delete-orphan")

    Index("ddspost__target_key", DdsPost.target_key)
    Index("ddspost__target_key2", DdsPost.target_key2)
    Index("ddspost__synapse_key", DdsPost.synapse_key)
    Index("ddspost__synapse_pow", DdsPost.synapse_pow)
    Index("ddspost__data_key", DdsPost.data_key)

    d.DdsPost = DdsPost

    class DdsStamp(Base):
        __tablename__ = "ddsstamp"

        id = Column(Integer, primary_key=True)
        stamp_key = Column(LargeBinary, nullable=False)
        signed_key = Column(LargeBinary, nullable=False)
        # str for sqlite bigint :(.
        version = Column(String, nullable=False)
        signing_key = Column(LargeBinary, nullable=False)
        difficulty = Column(Integer, nullable=False)
        revoked = Column(Boolean, nullable=False, default=False)
        first_seen = Column(UtcDateTime, nullable=False)
        children = relationship(\
            "DdsStamp",\
            foreign_keys="DdsStamp.signing_key",\
            primaryjoin="DdsStamp.signed_key == DdsStamp.signing_key",\
            passive_deletes="all")

    Index("ddsstamp__signed_key", DdsStamp.signed_key)
    Index("ddsstamp__signing_key", DdsStamp.signing_key)
    UniqueConstraint(\
        DdsStamp.signed_key, DdsStamp.version, DdsStamp.signing_key)

    d.DdsStamp = DdsStamp

    return d

class Db():
    def __init__(self, loop, url, schema=None):
        self.loop = loop
        self.url = url
        self.Session = None

        self.engine = None

        self.schema = schema

        self.is_sqlite = False
        self.sqlite_reader_count = 0
        self.sqlite_no_readers = threading.Event()
        self.sqlite_no_readers.set()
        self.sqlite_write_lock = threading.Lock()

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
        if self.sqlite_lock is not None:
            if read_only:
                with self.sqlite_write_lock:
                    self.sqlite_no_readers.clear()
                    self.sqlite_reader_count += 1
            else:
                self.sqlite_write_lock.acquire()
                if self.sqlite_reader_count > 0:
                    self.sqlite_no_readers.wait()

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
            if self.sqlite_lock is not None:
                if read_only:
                    self.sqlite_reader_count -= 1
                    if self.sqlite_reader_count == 0:
                        self.sqlite_no_readers.set()
                else:
                    self.sqlite_write_lock.release()

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
            version = float(r.value)
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
            version = 4

        #TODO: For now this is to get anyone who ran earlier dev builds to use
        # this new 4.9 thing correctly.
        if version == 5:
            _upgrade_5_dev0_to_5dev1(self)
            version = 4.91

        if version == 4:
            _upgrade_4_to_5_dev1(self)
            version = 4.91
        elif version == 4.9:
            _upgrade_5_dev0_to_5dev1(self)
            version = 4.91

        if version == 4.91:
            _upgrade_5_dev1_to_5dev2(self)
            version = 4.92

        if version == 4.92:
            _upgrade_5_dev2_to_5dev3(self)
            version = 4.93

        if version == 4.93:
            _upgrade_5_dev3_to_5dev4(self)
            version = 4.94

        if version == 4.94:
            _upgrade_5_dev4_to_5dev5(self)
            version = 4.95

        if version == 4.95:
            _upgrade_5_dev5_to_5dev6(self)
            version = 4.96

        if version == 4.96:
            _upgrade_5_dev6_to_5dev7(self)
            version = 4.97

        if version == 4.97:
            _upgrade_5_dev7_to_5dev8(self)
            version = 4.98

        if version == 4.98:
            _upgrade_5_dev8_to_5dev9(self)
            version = 4.99

        if version == 4.99:
            _upgrade_5_dev(self)

#        if version == 4:
#            _upgrade_4_to_5(self)
#            assert LATEST_SCHEMA_VERSION == 5
#            version = LATEST_SCHEMA_VERSION
#        elif version == 4.9:
#            _upgrade_5_dev_to_5(self)
#            assert LATEST_SCHEMA_VERSION == 5
#            version = LATEST_SCHEMA_VERSION

    def _create_schema(self):
        log.info("Creating schema.")
        self._create_or_update_schema()

    def _update_schema(self):
        log.info("Updating schema.")
        self._create_or_update_schema()

    def _create_or_update_schema(self):
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

    #FIXME: New stuff (sort properly later).
    AddressBook = d.AddressBook
    User = d.User
    DdsPost = d.DdsPost
    DdsStamp = d.DdsStamp
    Synapse = d.Synapse
    SynapseKey = d.SynapseKey
    Stamp = d.Stamp

def _update_node_state(sess, version):
    "Caller must call commit."

    q = sess.query(NodeState)\
        .filter(NodeState.key == consts.NSK_SCHEMA_VERSION)

    ns = q.first()

    if not ns:
        ns = NodeState()
        ns.key = consts.NSK_SCHEMA_VERSION
        sess.add(ns)

    ns.value = version if type(version) is str else str(version)

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

def _upgrade_4_to_5_dev1(db):
    log.warning("NOTE: Upgrading database schema from version 4 to 5-dev1.")

    db._update_schema()

    with db.open_session() as sess:
        _update_node_state(sess, 4.91)
        sess.commit()

    log.warning("NOTE: Database schema upgraded.")

def _upgrade_5_dev0_to_5dev1(db):
    log.warning(\
        "NOTE: Upgrading database schema from version 5-dev0 to 5-dev1.")

#    rebuild = False
#    db._update_schema()

    with db.open_session() as sess:
        ## Clean up DEV mess (REMOVE FOR FINAL).
        st = "select * from synapse where neuron_id is null"
        try:
            sess.execute(st)

            rebuild = True
            st = "drop table synapse"
            sess.execute(st)
            st = "drop table neuron"
            sess.execute(st)
            st = "drop table axonkey"
            sess.execute(st)
            sess.commit()
        except:
            sess.rollback()

        st = "select * from synapsekey where ekey is null"
        try:
            sess.execute(st)
        except:
            sess.rollback()
            try:
                rebuild = True
                st = "drop table synapse"
                sess.execute(st)
                st = "drop table synapsekey"
                sess.execute(st)
                sess.commit()
            except:
                sess.rollback()

        st = "select * from axon"
        try:
            sess.execute(st)

            rebuild = True
            st = "drop table axon"
            sess.execute(st)
            sess.commit()
        except:
            sess.rollback()

        st = "select * from axonkey"
        try:
            sess.execute(st)

            rebuild = True
            st = "drop table axonkey"
            sess.execute(st)
            sess.commit()
        except:
            sess.rollback()

        st = "select signing_key from ddspost"
        try:
            sess.execute(st)
        except:
            sess.rollback()
            try:
                rebuild = True
                st = "drop table ddspost"
                sess.execute(st)
                sess.commit()
            except:
                sess.rollback()

        st = "select timestamp from synapse"
        try:
            sess.execute(st)
        except:
            sess.rollback()
            try:
                rebuild = True
                st = "drop table synapse"
                sess.execute(st)
                st = "drop table synapsekey"
                sess.execute(st)
                sess.commit()
            except:
                sess.rollback()
        ##.

        # Our calc_log_distance calculation was broken in older versions! Code
        # in node.py will reset these if they were blank.
        sess.execute(update(Peer, bind=db.engine).values(distance=None))

        _update_node_state(sess, 4.91)

        sess.commit()

#    if rebuild:
#        db._update_schema()

    log.warning("NOTE: Database schema upgraded.")

def _upgrade_5_dev1_to_5dev2(db):
    log.warning(\
        "NOTE: Upgrading database schema from version 5-dev1 to 5-dev2.")

    with db.open_session() as sess:
        sess.execute("""
CREATE TABLE synapsekey_t (
    data_id BLOB NOT NULL,
    distance BLOB NOT NULL,
    synapse_id INTEGER NOT NULL,
    key_type INTEGER NOT NULL,
    ekey BLOB NOT NULL,
    last_access DATETIME,
    timestamp DATETIME NOT NULL,
    pow_difficulty INTEGER,
    PRIMARY KEY (data_id, synapse_id, key_type),
    FOREIGN KEY(synapse_id) REFERENCES synapse (id)
)
""")
        sess.execute("insert into synapsekey_t select * from synapsekey")
        sess.execute("drop table synapsekey")
        sess.execute("alter table synapsekey_t rename to synapsekey")

        _update_node_state(sess, 4.92)

        sess.commit()

    log.warning("NOTE: Database schema upgraded.")

def _upgrade_5_dev2_to_5dev3(db):
    log.warning(\
        "NOTE: Upgrading database schema from version 5-dev2 to 5-dev3.")

    with db.open_session() as sess:
        sess.execute("""
CREATE TABLE nodestate_t (
    "key" VARCHAR NOT NULL,
    value VARCHAR,
    PRIMARY KEY ("key")
);
""")
        sess.execute("insert into nodestate_t select * from nodestate")
        sess.execute("drop table nodestate")
        sess.execute("alter table nodestate_t rename to nodestate")

        _update_node_state(sess, 4.93)

        sess.commit()

    log.warning("NOTE: Database schema upgraded.")

def _upgrade_5_dev3_to_5dev4(db):
    log.warning(\
        "NOTE: Upgrading database schema from version 5-dev3 to 5-dev4.")

    t_integer = "INTEGER" if db.is_sqlite else "integer"

    with db.open_session() as sess:
        try:
            sess.execute(\
                "ALTER TABLE ddspost add column score {}".format(t_integer))
        except:
            sess.rollback()

        _update_node_state(sess, 4.94)

        sess.commit()

    log.warning("NOTE: Database schema upgraded.")

def _upgrade_5_dev4_to_5dev5(db):
    log.warning(\
        "NOTE: Upgrading database schema from version 5-dev4 to 5-dev5.")

    from maalstroom.dds import DEFAULT_FEED_KEY

    with db.open_session() as sess:
        feed = sess.query(NodeState)\
            .filter(NodeState.key == DEFAULT_FEED_KEY)\
            .delete(synchronize_session=False)

        _update_node_state(sess, 4.95)

        sess.commit()

    log.warning("NOTE: Database schema upgraded.")

def _upgrade_5_dev5_to_5dev6(db):
    log.warning(\
        "NOTE: Upgrading database schema from version 5-dev5 to 5-dev6.")

    t_bytea = "BLOB" if db.is_sqlite else "bytea"

    with db.open_session() as sess:
        try:
            sess.execute(\
                "ALTER TABLE ddspost add column target_key2 {}".format(t_bytea))
            sess.execute(\
                "CREATE INDEX ddspost__target_key2 ON ddspost (target_key2)")
        except:
            sess.rollback()

        _update_node_state(sess, 4.96)

        sess.commit()

    log.warning("NOTE: Database schema upgraded.")

def _upgrade_5_dev6_to_5dev7(db):
    log.warning(\
        "NOTE: Upgrading database schema from version 5-dev6 to 5-dev7.")

    with db.open_session() as sess:
        try:
            sess.execute("select id from stamp")
        except:
            sess.rollback()
            try:
                rebuild = True
                st = "drop table stamp"
                sess.execute(st)
                sess.commit()
            except:
                sess.rollback()

        _update_node_state(sess, 4.97)

        sess.commit()

    log.warning("NOTE: Database schema upgraded.")

def _upgrade_5_dev7_to_5dev8(db):
    log.warning(\
        "NOTE: Upgrading database schema from version 5-dev7 to 5-dev8.")

    with db.open_session() as sess:
        try:
            sess.execute("select id from ddsstamp")
        except:
            sess.rollback()
            try:
                rebuild = True
                st = "drop table ddsstamp"
                sess.execute(st)
                sess.commit()
            except:
                sess.rollback()

        _update_node_state(sess, 4.98)

        sess.commit()

    log.warning("NOTE: Database schema upgraded.")

def _upgrade_5_dev8_to_5dev9(db):
    log.warning(\
        "NOTE: Upgrading database schema from version 5-dev8 to 5-dev9.")

    with db.open_session() as sess:
        try:
            sess.execute("select stamp_key from ddsstamp")
            sess.execute("select stamp_id from stamp")
        except:
            sess.rollback()
            try:
                rebuild = True
                st = "drop table ddsstamp"
                sess.execute(st)
                st = "drop table stamp"
                sess.execute(st)
                sess.commit()
            except:
                sess.rollback()

        _update_node_state(sess, 4.99)

        sess.commit()

    log.warning("NOTE: Database schema upgraded.")

def _upgrade_5_dev(db):
    log.warning("NOTE: Possibly upgrading v5-dev database schema.")

    db._update_schema()

    log.warning("NOTE: Done possibly upgrading database schema.")

sqlalchemy_pre_1_0_15 = parse_version(sqlalchemy__version__)\
    < parse_version("1.0.15")
