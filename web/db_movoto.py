# -*- coding: utf-8 -*-
import MySQLdb
import functools
import threading
from MySQLdb.cursors import DictCursor
from MySQLdb.cursors import SSDictCursor
from MySQLdb.cursors import SSCursor
import os

settings = {
    
}

class SqlHelper(object):
    def __init__(self, db, use_connection_pool=False, **kwargs):
        self.default_port_map = {"mysql":3306, "mssql":1443}
        self.use_connection_pool = use_connection_pool
        self.__getConfig(db)
        self.__getSlaveConfig(db)
        _connection_manager.register_db(db, settings.DATABASES[db], use_connection_pool)

    def __getConfig(self, db):
        self.alias = db
        self.type = settings.DATABASES[db]["TYPE"]
        self.db = settings.DATABASES[db]["NAME"]
        self.host = settings.DATABASES[db]["HOST"]
        self.user = settings.DATABASES[db]["USER"]
        self.pwd = settings.DATABASES[db]["PASSWORD"]
        port = settings.DATABASES[db].get("PORT", None)
        if port:
            self.port = port
        else:
            self.port = self.default_port_map.get(self.type, 0)
            if self.port:
                settings.DATABASES[db]['PORT'] = self.port
            else:
                raise Exception("unknow database type, please add port number in config!")

    # master-slave db
    def __getSlaveConfig(self, db):
        if 'SLAVE' in settings.DATABASES[db]:
            slave = settings.DATABASES[db]['SLAVE']
            slave['READ_ONLY'] = True
            if 'PORT' not in slave:
                if slave['TYPE'] == 'mysql':
                    slave['PORT'] = '3306'
                elif slave['TYPE'] == 'mssql':
                    slave['PORT'] = '1433'
                else:
                    print "unknow databse type, please add port."

            self.slave = slave
            settings.DATABASES[self.getSlaveAlias()] = self.slave
        else:
            self.slave = None

    def getSlaveAlias(self):
        if self.slave:
            return self.alias + "_" + 'SLAVE'
        else:
            return None

    def getConnection(self, read_only_slave=False):
        '''
        get a connection within the current thread according to the db name
        '''
        if read_only_slave and self.slave:
            return _transaction_ctx.get_db_conn(self.getSlaveAlias())
        else:
            return _transaction_ctx.get_db_conn(self.alias)

    def getStandaloneConnection(self, read_only_slave=False):
        '''
        get a connection without transaction management according to the db name
        '''
        if read_only_slave and self.slave:
            return _connection_manager.get_connection(self.getSlaveAlias())
        else:
            return _connection_manager.get_connection(self.alias)

    def getCursor(self, read_only_slave=False, dict_result=False, yieldCursor=False):
        return self._getCursor(self.getConnection(read_only_slave), dict_result, yieldCursor)

    def _getCursor(self, conn, dict_result=False, yieldCursor=False):
        #use different cursor for different purpose for mysql
        if self.type == 'mysql':
            if dict_result and yieldCursor:
                return conn.cursor(cursorclass=SSDictCursor)
            if dict_result and not yieldCursor:
                return conn.cursor(cursorclass=DictCursor)
            if not dict_result and yieldCursor:
                return conn.cursor(cursorclass=SSCursor)
            if not dict_result and not yieldCursor:
                return conn.cursor()

        if self.type == 'mssql':
            if dict_result:
                return conn.cursor(as_dict=True)
            else:
                return conn.cursor()

    def closeConnection(self):
        '''
        close the connection within the current thread according to the db name
        '''
        _transaction_ctx.close_db_conn(self.alias)
        if self.slave:
            _transaction_ctx.close_db_conn(self.getSlaveAlias())

    def closePool(self):
        '''
        close the connection pool in process scope. 
        Pool is in process scope while connection is in thread scope
        '''
        _connection_manager.close_pool(self.alias)

    def commit(self):
        _transaction_ctx.commit(self.alias)

    def rollback(self):
        _transaction_ctx.rollback(self.alias)

    # a decorator for connecting before querying and disconnct after querying
    def query(self,fn):
        @functools.wraps(fn)
        def execute(self, *args):
            self.getConnection()
            result = fn(self, *args)
            return result
        return execute

    @transactional
    def getOneBySql(self, sql, *args, **kwargs):
        read_master = kwargs.get('read_master', False)
        dict_result = kwargs.get('dict_result', False)
        cur = self.getCursor(read_only_slave=True if not read_master else False, dict_result=dict_result)
        if not args:
            args = None
        cur.execute(sql, args)
        result = cur.fetchone()
        return result

    @transactional
    def getAllBySql(self, sql, *args, **kwargs):
        read_master = kwargs.get('read_master', False)
        dict_result = kwargs.get('dict_result', False)
        cur = self.getCursor(read_only_slave=True if not read_master else False, dict_result=dict_result)
        if self.type == 'mysql':
            if not args:
                args = None
            cur.execute(sql, args)
        else:
            if not args:
                cur.execute(sql)
            else:
                cur.execute(sql, args)
        results = cur.fetchall()
        return results

    def yieldAllBySql(self, sql, *args, **kwargs):
        #it's meaningless to make yieldAllBySql inside a transaction
        try:
            read_master = kwargs.get('read_master', False)
            dict_result = kwargs.get('dict_result', False)
            conn = self.getStandaloneConnection(not read_master)
            cur = self._getCursor(conn, dict_result=dict_result, yieldCursor=True)
            if self.type == 'mysql':
                if not args:
                    args = None
                cur.execute(sql, args)
            else:
                if not args:
                    cur.execute(sql)
                else:
                    cur.execute(sql, args)
            result = cur.fetchone()
            while result:
                yield result
                result = cur.fetchone()
        finally:
            cur.close()
            conn.close()


    @transactional
    def executeBySql(self, sql, *args):
        cur = self.getCursor()
        if not args:
            args = None
        result = cur.execute(sql, args)
        return result

    @transactional
    def updateBySql(self, sql, *args):
        cur = self.getCursor()
        if not args:
            args = None
        result = cur.execute(sql, args)
        return result

    @transactional
    def deleteBySql(self, sql, *args):
        cur = self.getCursor()
        if not args:
            args = None
        result = cur.execute(sql, args)
        return result

    @transactional
    def insertBySql(self, sql, *args):
        cur = self.getCursor()
        if not args:
            args = None
        result = cur.execute(sql, args)
        insertId = cur.lastrowid
        return result, insertId

    @transactional
    def insertManyBySql(self, sql, valueList):
        cur = self.getCursor()
        # current version of mysqldb has a bug: which is only allow "values" in lower case.
        # sql = sql.lower()
        result = cur.executemany(sql, valueList)
        return result

    @transactional
    def executeManyBySql(self, sql, valueList):
        cur = self.getCursor()
        # current version of mysqldb has a bug: which is only allow "values" in lower case.
        # sql = sql.lower()
        result = cur.executemany(sql, valueList)
        return result

class SqlPool(object):
    def __init__(self, db, maxcached=10, maxshared=10, maxconnections=0):
        self.conn = None
        self.maxcached = maxcached
        self.maxshared = maxshared
        self.maxconnections = maxconnections
        self.__getConfig(db)
        # ==============================
        # use DBUtils.PooledDB ??
        # ==============================
        from DBUtils.PooledDB import PooledDB
        self.conn_pool = PooledDB(import_db_lib(self.type), maxcached=self.maxcached, maxshared=self.maxshared,
                                  maxconnections=self.maxconnections,
                                  host=self.host, port=self.port, user=self.user, passwd=self.pwd, db=self.db, charset="utf8")

    def __getConfig(self, db):
        self.type = settings.DATABASES[db]["TYPE"]
        self.db = settings.DATABASES[db]["NAME"]
        self.host = settings.DATABASES[db]["HOST"]
        self.user = settings.DATABASES[db]["USER"]
        self.pwd = settings.DATABASES[db]["PASSWORD"]
        if settings.DATABASES[db].get("PORT"):
            self.port = settings.DATABASES[db]["PORT"]
        else:
            if self.type == 'mysql':
                self.port = 3306
            elif self.type == 'mssql':
                self.port = 1433
            else:
                print "unknow databse type, please add port."

    def getConnection(self):
        '''
        get a connection
        '''
        try:
            return self.conn_pool.connection()
        except Exception, e:
            print e
            raise (NameError, "failed to connect database")

    def close(self):
        self.conn_pool.close()

class __TransactionCtx(threading.local):  # threading.local ?
    '''Thread local object that holds connection info.'''
    def __init__(self):
        self.connections = {}
        self.transactions = {}

    def is_db_conn_init(self, db):
        return withpid(db) in self.connections

    def init_db_conn(self, db):
        self.connections[withpid(db)] = _connection_manager.get_connection(db)

    def get_db_conn(self, db):
        if not self.is_db_conn_init(db):
            self.init_db_conn(db)
        return self.connections[withpid(db)]

    def increase_transaction_count(self):
        self.transactions[withpid('transaction')] = self.transactions.get(withpid('transaction'), 0) + 1

    def decrease_transaction_count(self):
        self.transactions[withpid('transaction')] = self.transactions[withpid('transaction')] - 1

    def get_transaction_count(self):
        return self.transactions.get(withpid('transaction'), 0)

    def cleanup(self):
        for db_withpid, conn in self.connections.iteritems():
            try:
                _connection_manager.close_connection(conn)
            except:
                pass
        self.connections.clear()
        self.transactions[withpid('transaction')] = 0

    def close_db_conn(self, db):
        if withpid(db) in self.connections:
            conn = self.connections.pop(withpid(db))
            _connection_manager.close_connection(conn)

    def cursor(self, db):
        '''
        Return cursor
        '''
        return self.connections[withpid(db)].cursor()

    def commit(self):
        for db, conn in self.connections.iteritems():
            _connection_manager.commit(withoutpid(db), conn)

    def rollback(self):
        for db, conn in self.connections.iteritems():
            _connection_manager.rollback(conn)

# _transaction_ctx = __TransactionCtx()
class __TransactionManager(object):
    '''_TransactionManager object that can handle transactions.'''
    def __enter__(self):
        self.enter_transaction()
        return self

    def __exit__(self, exctype, excvalue, traceback):
        self.leave_transaction()
        if _transaction_ctx.get_transaction_count() == 0:
            try:
                if exctype is None:
                    self.commit()
                else:
                    self.rollback()
            finally:
                self.end()

    def commit(self):
        _transaction_ctx.commit()

    def rollback(self):
        _transaction_ctx.rollback()

    def leave_transaction(self):
        _transaction_ctx.decrease_transaction_count()

    def enter_transaction(self):
        _transaction_ctx.increase_transaction_count()

    def end(self):
        _transaction_ctx.cleanup()

# decorator to wrap db query function in transaction.
def transactional(func):
    @functools.wraps(func)
    def _wrapper(*args, **kw):
        with __TransactionManager():
            return func(*args, **kw)
    return _wrapper

def transaction_context(sqlHelper):
    
    # with _withTransactionContext(sqlHelper) as cursor:
    #     cursor.execute()
    class _withTransactionContext(__TransactionManager):
        def __init__(self, sqlHelper):
            self.sqlHelper = sqlHelper
        def __enter__(self):
            super(_withTransactionContext, self).__enter__()
            if self.sqlHelper.slave:
                return self.sqlHelper.getCursor(), self.sqlHelper.getCursor(read_only_slave=True)
            else:
                return self.sqlHelper.getCursor()
        def __exit__(self, exctype, excvalue, traceback):
            super(_withTransactionContext, self).__exit__(exctype, excvalue, traceback)
    
    return _withTransactionContext(sqlHelper)


def import_db_lib(type):
    if type == 'mysql':
        return MySQLdb  # or use pymysql ?
    elif type == 'mssql':
        import pymssql
        return pymssql

def withpid(alias):
    return alias +'#@#'+str(os.getpid())

def withoutpid( alias):
    return alias.split('#@#')[0]


class __ConnectionManager:
    def __init__(self):
        self.db_pool_container = {}
        self.db_conf_container = {}

    def register_db(self, db, conf, use_connection_pool):
        if not withpid(db) in self.db_conf_container:
            self.db_conf_container[withpid(db)] = conf
            if use_connection_pool:
                self.db_pool_container[withpid(db)] = SqlPool(db)

            if 'SLAVE' in conf:
                self.register_db(db+"_"+"SLAVE", conf['SLAVE'], use_connection_pool)

    def get_connection(self, db):
        if withpid(db) in self.db_pool_container:
            return self.db_pool_container[withpid(db)].getConnection()
        else:
            if self.db_conf_container[withpid(db)]['TYPE'] == 'mssql':
                return import_db_lib(self.db_conf_container[withpid(db)]['TYPE']).connect(
                                                                              host=self.db_conf_container[withpid(db)]['HOST'],
                                                                              user=self.db_conf_container[withpid(db)]['USER'],
                                                                              password=self.db_conf_container[withpid(db)]['PASSWORD'],
                                                                              database=self.db_conf_container[withpid(db)]['NAME'])
            else:
                return import_db_lib(self.db_conf_container[withpid(db)]['TYPE']).connect(
                                                                             self.db_conf_container[withpid(db)]['HOST'],
                                                                             self.db_conf_container[withpid(db)]['USER'],
                                                                             self.db_conf_container[withpid(db)]['PASSWORD'],
                                                                             self.db_conf_container[withpid(db)]['NAME'],
                                                                             self.db_conf_container[withpid(db)]['PORT'],
                                                                             charset="utf8")

    def close_connection(self, conn):
        if conn and self.is_connection_open(conn):
            conn.close()

    def is_connection_open(self, conn):
        try:
            conn.ping()
            return True
        except:
            return False

    def close_pool(self, db):
        if withpid(db) in self.db_pool_container:
            self.db_pool_container[withpid(db)].close()

    def commit(self, db, conn):
        if 'READ_ONLY' in self.db_conf_container[withpid(db)]:
            conn.rollback()
        else:
            conn.commit()

    def rollback(self, conn):
        conn.rollback()


_connection_manager = __ConnectionManager()
_transaction_ctx = __TransactionCtx()


