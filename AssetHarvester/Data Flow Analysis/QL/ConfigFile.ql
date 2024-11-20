/*
 *  Captures secret-asset pairs where the secrets and assets are present in a config file (e.g. yml file) and
 *  read from the config file and passed into the driver functions as dictionary variable.
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources
import semmle.python.Concepts

class AiomysqlCall extends DataFlow::Node {
  AiomysqlCall() {
    this = API::moduleImport("aiomysql").getMember("connect").getACall() or
    this = API::moduleImport("aiomysql").getMember("create_pool").getACall()
  }
}

class AiopgCall extends DataFlow::Node {
  AiopgCall() {
    this = API::moduleImport("aiopg").getMember("connect").getACall() or
    this = API::moduleImport("aiopg").getMember("create_pool").getACall()
  }
}

class AsyncpgCall extends DataFlow::Node {
  AsyncpgCall() {
    this = API::moduleImport("asyncpg").getMember("connect").getACall() or
    this = API::moduleImport("asyncpg").getMember("create_pool").getACall()
  }
}

class MysqlConnectorCall extends DataFlow::Node {
  MysqlConnectorCall() {
    this = API::moduleImport("mysql").getMember("connector").getMember("connect").getACall() or
    this = API::moduleImport("mysql").getMember("connector").getMember("MySQLConnection").getACall()
  }
}

class MysqlclientCall extends DataFlow::Node {
  MysqlclientCall() { this = API::moduleImport("MySQLdb").getMember("connect").getACall() }
}

class PsycopgCall extends DataFlow::Node {
  PsycopgCall() {
    this = API::moduleImport("psycopg").getMember("connect").getACall() or
    this = API::moduleImport("psycopg2").getMember("connect").getACall()
  }
}

class PymssqlConnectCall extends DataFlow::Node {
  PymssqlConnectCall() {
    this = API::moduleImport("pymssql").getMember("connect").getACall() or
    this = API::moduleImport("_mssql").getMember("connect").getACall()
  }
}

class PymssqlConnectionCall extends DataFlow::Node {
  PymssqlConnectionCall() {
    this = API::moduleImport("pymssql").getMember("Connection").getACall() or
    this = API::moduleImport("_mssql").getMember("MSSQLConnection").getACall()
  }
}

class PymysqlCall extends DataFlow::Node {
  PymysqlCall() {
    this = API::moduleImport("pymysql").getMember("connect").getACall() or
    this = API::moduleImport("pymysql").getMember("connections").getMember("Connection").getACall() or
    this = API::moduleImport("pymysql").getMember("Connection").getACall()
  }
}

class PymongoCall extends DataFlow::Node {
  PymongoCall() {
    this = API::moduleImport("pymongo").getMember("connect").getACall() or
    this =
      API::moduleImport("pymongo").getMember("mongo_client").getMember("MongoClient").getACall() or
    this = API::moduleImport("pymongo").getMember("MongoClient").getACall()
  }
}

class PeeweePostgresqlDatabaseCall extends DataFlow::Node {
  PeeweePostgresqlDatabaseCall() {
    this = API::moduleImport("peewee").getMember("PostgresqlDatabase").getACall()
  }
}

class PeeweeMySQLDatabaseCall extends DataFlow::Node {
  PeeweeMySQLDatabaseCall() {
    this = API::moduleImport("peewee").getMember("MySQLDatabase").getACall()
  }
}

class JayDeBeAPICall extends DataFlow::Node {
  JayDeBeAPICall() {
    this = API::moduleImport("jaydebeapi").getMember("connect").getACall()
  }
}

class DriverCall extends DataFlow::Node {
  DriverCall() {
    this instanceof AiomysqlCall or
    this instanceof AiopgCall or
    this instanceof AsyncpgCall or
    this instanceof MysqlConnectorCall or
    this instanceof MysqlclientCall or
    this instanceof PsycopgCall or
    this instanceof PymssqlConnectCall or
    this instanceof PymssqlConnectionCall or
    this instanceof PymysqlCall or
    this instanceof PymongoCall or
    this instanceof PeeweePostgresqlDatabaseCall or
    this instanceof PeeweeMySQLDatabaseCall or
    this instanceof JayDeBeAPICall
  }

  string getDBType() {
    if
      this instanceof AiomysqlCall or
      this instanceof PymysqlCall or
      this instanceof MysqlclientCall or
      this instanceof MysqlConnectorCall or
      this instanceof PeeweeMySQLDatabaseCall
    then result = "mysql"
    else
      if
        (
          this instanceof AsyncpgCall or
          this instanceof AiopgCall or
          this instanceof PsycopgCall or
          this instanceof PeeweePostgresqlDatabaseCall
        )
      then result = "postgresql"
      else
        if (this instanceof PymssqlConnectCall or this instanceof PymssqlConnectionCall)
        then result = "sqlserver"
        else
          if this instanceof PymongoCall
          then result = "mongodb"
          else result = "ORM"
  }
}

class ConfigSubscript extends DataFlow::Node {
  DataFlow::CallCfgNode call;
  DataFlow::Node arg;
  string keyname;

  ConfigSubscript() {
    call instanceof DriverCall and
    (arg = call.getArgByName(_) or arg = call.getArg(_)) and
    this.asExpr() = arg.asCfgNode().getAChild*().getNode().(Subscript) and
    keyname = arg.asCfgNode().getAChild*().getNode().(StrConst).getS()
  }

  DataFlow::CallCfgNode getCall() { result = call }

  DataFlow::Node getArg() { result = arg }

  string getKeyName() { result = keyname }
}

class HostSink extends DataFlow::Node {
  DataFlow::CallCfgNode call;

  HostSink() {
    if
      (
        call instanceof MysqlclientCall or
        call instanceof PymssqlConnectCall or
        call instanceof PymysqlCall or
        call instanceof PymongoCall
      ) and
      this = call.getArg(0)
    then this = call.getArg(0)
    else (
      call instanceof DriverCall and
      (
        this = call.getArgByName("host") or
        this = call.getArgByName("server")
      )
    )
  }

  DataFlow::CallCfgNode getCall() { result = call }
}

class PortSink extends DataFlow::Node {
  DataFlow::CallCfgNode call;

  PortSink() {
    if call instanceof MysqlclientCall and this = call.getArg(4)
    then this = call.getArg(4)
    else
      if call instanceof PymongoCall and this = call.getArg(1)
      then this = call.getArg(1)
      else (
        call instanceof DriverCall and
        this = call.getArgByName("port")
      )
  }

  DataFlow::CallCfgNode getCall() { result = call }
}

class DBSink extends DataFlow::Node {
  DataFlow::CallCfgNode call;

  DBSink() {
    if
      (
        call instanceof MysqlclientCall or
        call instanceof PymssqlConnectCall or
        call instanceof PymysqlCall
      ) and
      this = call.getArg(3)
    then this = call.getArg(3)
    else
      if
        (call instanceof PeeweePostgresqlDatabaseCall or call instanceof PeeweeMySQLDatabaseCall) and
        this = call.getArg(0)
      then this = call.getArg(0)
      else (
        call instanceof DriverCall and
        (
          this = call.getArgByName("db") or
          this = call.getArgByName("database") or
          this = call.getArgByName("dbname")
        )
      )
  }

  DataFlow::CallCfgNode getCall() { result = call }
}

class UserSink extends DataFlow::Node {
  DataFlow::CallCfgNode call;

  UserSink() {
    if
      (
        call instanceof MysqlclientCall or
        call instanceof PymssqlConnectCall or
        call instanceof PymysqlCall
      ) and
      this = call.getArg(1)
    then this = call.getArg(1)
    else (
      call instanceof DriverCall and
      (
        this = call.getArgByName("user") or
        this = call.getArgByName("username")
      )
    )
  }

  DataFlow::CallCfgNode getCall() { result = call }
}

class PasswordSink extends DataFlow::Node {
  DataFlow::CallCfgNode call;

  PasswordSink() {
    if
      (
        call instanceof MysqlclientCall or
        call instanceof PymssqlConnectCall or
        call instanceof PymysqlCall
      ) and
      this = call.getArg(2)
    then this = call.getArg(2)
    else (
      call instanceof DriverCall and
      (
        this = call.getArgByName("password") or
        this = call.getArgByName("passwd")
      )
    )
  }

  DataFlow::CallCfgNode getCall() { result = call }
}

predicate getHost(ConfigFileSource source, string hostkey, string callLocation, string dbType) {
  if
    exists(ConfigSubscript csub, HostSink host |
      AssetFlow::flow(source, csub) and
      host.getCall() = csub.getCall() and
      host = csub.getArg()
    )
  then
    exists(ConfigSubscript csub, HostSink host |
      AssetFlow::flow(source, csub) and
      host.getCall() = csub.getCall() and
      host = csub.getArg()
    |
      hostkey = csub.getKeyName() and
      callLocation = csub.getCall().getLocation().toString() and
      dbType = csub.getCall().(DriverCall).getDBType()
    )
  else (
    hostkey = "Not Found" and callLocation = "Not Found" and dbType = "Not Found"
  )
}

predicate getPort(ConfigFileSource source, string portKey) {
  if
    exists(ConfigSubscript csub, PortSink port |
      AssetFlow::flow(source, csub) and
      port.getCall() = csub.getCall() and
      port = csub.getArg()
    )
  then
    exists(ConfigSubscript csub, PortSink port |
      AssetFlow::flow(source, csub) and
      port.getCall() = csub.getCall() and
      port = csub.getArg()
    |
      portKey = csub.getKeyName()
    )
  else portKey = "Not Found"
}

predicate getDB(ConfigFileSource source, string dbKey) {
  if
    exists(ConfigSubscript csub, DBSink db |
      AssetFlow::flow(source, csub) and
      db.getCall() = csub.getCall() and
      db = csub.getArg()
    )
  then
    exists(ConfigSubscript csub, DBSink db |
      AssetFlow::flow(source, csub) and
      db.getCall() = csub.getCall() and
      db = csub.getArg()
    |
      dbKey = csub.getKeyName()
    )
  else dbKey = "Not Found"
}

predicate getUser(ConfigFileSource source, string userKey) {
  if
    exists(ConfigSubscript csub, UserSink user |
      AssetFlow::flow(source, csub) and
      user.getCall() = csub.getCall() and
      user = csub.getArg()
    )
  then
    exists(ConfigSubscript csub, UserSink user |
      AssetFlow::flow(source, csub) and
      user.getCall() = csub.getCall() and
      user = csub.getArg()
    |
      userKey = csub.getKeyName()
    )
  else userKey = "Not Found"
}

predicate getPassword(ConfigFileSource source, string passwordKey) {
  if
    exists(ConfigSubscript csub, PasswordSink password |
      AssetFlow::flow(source, csub) and
      password.getCall() = csub.getCall() and
      password = csub.getArg()
    )
  then
    exists(ConfigSubscript csub, PasswordSink password |
      AssetFlow::flow(source, csub) and
      password.getCall() = csub.getCall() and
      password = csub.getArg()
    |
      passwordKey = csub.getKeyName()
    )
  else passwordKey = "Not Found"
}

class ConfigFileSource extends DataFlow::Node {
  ConfigFileSource() { this instanceof PKGUtilSource or this instanceof OpenCallSource }

  string getFileName() {
    if this instanceof PKGUtilSource
    then result = this.(PKGUtilSource).getFileName()
    else
      if this instanceof OpenCallSource
      then result = this.(OpenCallSource).getFileName()
      else result = "Not Found"
  }
}

class OpenCallSource extends DataFlow::Node {
  string filename;

  OpenCallSource() {
    (
      this = API::moduleImport("os").getMember("open").getACall().getArg(0)
      or
      exists(Call c | c.getFunc().toString() = "open" and c.getArg(0) = this.asExpr())
    ) and
    filename = this.asCfgNode().getAChild*().getNode().(StrConst).getS()
  }

  string getFileName() { result = filename }
}

class PKGUtilSource extends DataFlow::Node {
  string filename;

  PKGUtilSource() {
    exists(DataFlow::MethodCallNode call |
      call = API::moduleImport("pkgutil").getMember("get_data").getACall() and this = call
    |
      filename = call.getArg(1).asCfgNode().getAChild*().getNode().(StrConst).getS()
    )
  }

  string getFileName() { result = filename }
}

module AssetFlowConfiguration implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof ConfigFileSource }

  predicate isSink(DataFlow::Node sink) { sink instanceof ConfigSubscript }
}

module AssetFlow = TaintTracking::Global<AssetFlowConfiguration>;

from
  ConfigFileSource cfgSource, string callLocation, string hostKey, string portKey, string dbKey,
  string userKey, string passwordKey, string dbType
where
  getHost(cfgSource, hostKey, callLocation, dbType) and
  getPort(cfgSource, portKey) and
  getDB(cfgSource, dbKey) and
  getUser(cfgSource, userKey) and
  getPassword(cfgSource, passwordKey) and
  hostKey != "Not Found"
select cfgSource.getFileName() as fileName, hostKey, portKey, dbKey, userKey, passwordKey, callLocation, dbType
