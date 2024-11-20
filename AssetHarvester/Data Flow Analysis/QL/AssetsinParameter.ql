/**
 * @name Assets Passed in Driver Function Parameters
 * @description Path query for finding assets passed in the parameter of Driver functions
 * @kind problem
 * @precision high
 * @id python/assets-in-param
 * @tags security
 * @problem.severity warning
 */

/*
 *  Captures secret-asset pairs where the secrets are present in string constants and passed directly to
 *  the positional or named arguments of driver functions either through variables or through dictionary.
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

class AssetValueSource extends DataFlow::Node {
  AssetValueSource() {
    exists(StrConst str, IntegerLiteral lt |
      str = this.asCfgNode().getNode() or lt = this.asCfgNode().getNode()
    )
  }
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

module AssetFlowConfiguration implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof AssetValueSource }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof HostSink or
    sink instanceof PortSink or
    sink instanceof UserSink or
    sink instanceof DBSink or
    sink instanceof PasswordSink
  }
}

module AssetFlow = DataFlow::Global<AssetFlowConfiguration>;

class Host extends AssetValueSource {
  DataFlow::CallCfgNode call;
  HostSink hostSink;

  Host() {
    call instanceof DriverCall and
    AssetFlow::flow(this, hostSink) and
    hostSink.getCall() = call
  }

  DataFlow::CallCfgNode getCall() { result = call }
}

predicate getHost(DataFlow::CallCfgNode call, string hostValue, string hostLocation) {
  if exists(Host host | host.getCall() = call and host.asCfgNode().hasCompletePointsToSet())
  then
    exists(Host host | host.getCall() = call |
      hostValue = host.asCfgNode().pointsTo().toString() and
      hostLocation = host.getLocation().toString()
    )
  else
    if exists(Host host | host.getCall() = call and not host.asCfgNode().hasCompletePointsToSet())
    then
      exists(Host host | host.getCall() = call |
        hostValue = host.asExpr().(StrConst).getS() and hostLocation = host.getLocation().toString()
      )
    else (
      hostValue = "Not Found" and hostLocation = "Not Found"
    )
}

class Port extends AssetValueSource {
  DataFlow::CallCfgNode call;
  PortSink portSink;

  Port() {
    call instanceof DriverCall and
    AssetFlow::flow(this, portSink) and
    call = portSink.getCall()
  }

  DataFlow::CallCfgNode getCall() { result = call }
}

predicate getPort(DataFlow::CallCfgNode call, string portValue, string portLocation) {
  if exists(Port port | port.getCall() = call and port.asCfgNode().hasCompletePointsToSet())
  then
    exists(Port port | port.getCall() = call |
      portValue = port.asCfgNode().pointsTo().toString() and
      portLocation = port.getLocation().toString()
    )
  else
    if exists(Port port | port.getCall() = call and not port.asCfgNode().hasCompletePointsToSet())
    then
      exists(Port port | port.getCall() = call |
        portValue = port.asExpr().(IntegerLiteral).getN() and
        portLocation = port.getLocation().toString()
      )
    else (
      portValue = "Not Found" and portLocation = "Not Found"
    )
}

class DB extends AssetValueSource {
  DataFlow::CallCfgNode call;
  DBSink dbSink;

  DB() {
    call instanceof DriverCall and
    AssetFlow::flow(this, dbSink) and
    dbSink.getCall() = call
  }

  DataFlow::CallCfgNode getCall() { result = call }
}

predicate getDB(DataFlow::CallCfgNode call, string dbValue, string dbLocation) {
  if exists(DB db | db.getCall() = call and db.asCfgNode().hasCompletePointsToSet())
  then
    exists(DB db | db.getCall() = call |
      dbValue = db.asCfgNode().pointsTo().toString() and
      dbLocation = db.getLocation().toString()
    )
  else
    if exists(DB db | db.getCall() = call and not db.asCfgNode().hasCompletePointsToSet())
    then
      exists(DB db | db.getCall() = call |
        dbValue = db.asExpr().(StrConst).getS() and
        dbLocation = db.getLocation().toString()
      )
    else (
      dbValue = "Not Found" and dbLocation = "Not Found"
    )
}

class User extends AssetValueSource {
  DataFlow::CallCfgNode call;
  UserSink userSink;

  User() {
    call instanceof DriverCall and
    AssetFlow::flow(this, userSink) and
    userSink.getCall() = call
  }

  DataFlow::CallCfgNode getCall() { result = call }
}

predicate getUser(DataFlow::CallCfgNode call, string userValue, string userLocation) {
  if exists(User user | user.getCall() = call and user.asCfgNode().hasCompletePointsToSet())
  then
    exists(User user | user.getCall() = call |
      userValue = user.asCfgNode().pointsTo().toString() and
      userLocation = user.getLocation().toString()
    )
  else
    if exists(User user | user.getCall() = call and not user.asCfgNode().hasCompletePointsToSet())
    then
      exists(User user | user.getCall() = call |
        userValue = user.asExpr().(StrConst).getS() and
        userLocation = user.getLocation().toString()
      )
    else (
      userValue = "Not Found" and userLocation = "Not Found"
    )
}

class Password extends AssetValueSource {
  DataFlow::CallCfgNode call;
  PasswordSink passSink;

  Password() {
    call instanceof DriverCall and
    AssetFlow::flow(this, passSink) and
    passSink.getCall() = call
  }

  DataFlow::CallCfgNode getCall() { result = call }
}

predicate getPassword(DataFlow::CallCfgNode call, string passwordValue, string passwordLocation) {
  if exists(Password pass | pass.getCall() = call and pass.asCfgNode().hasCompletePointsToSet())
  then
    exists(Password pass | pass.getCall() = call |
      passwordValue = pass.asCfgNode().pointsTo().toString() and
      passwordLocation = pass.getLocation().toString()
    )
  else
    if
      exists(Password pass |
        pass.getCall() = call and not pass.asCfgNode().hasCompletePointsToSet()
      )
    then
      exists(Password pass | pass.getCall() = call |
        passwordValue = pass.asExpr().(StrConst).getS() and
        passwordLocation = pass.getLocation().toString()
      )
    else (
      passwordValue = "Not Found" and passwordLocation = "Not Found"
    )
}

from
  DriverCall call, string hostValue, string hostLocation, string portValue, string portLocation,
  string dbValue, string dbLocation, string userValue, string userLocation, string passwordValue,
  string passwordLocation
where
  getHost(call, hostValue, hostLocation) and
  getPort(call, portValue, portLocation) and
  getDB(call, dbValue, dbLocation) and
  getUser(call, userValue, userLocation) and
  getPassword(call, passwordValue, passwordLocation)
select call.getLocation().toString() as callLocation, hostValue, hostLocation, portValue,
  portLocation, dbValue, dbLocation, userValue, userLocation, passwordValue, passwordLocation,
  call.getDBType() as dbType
