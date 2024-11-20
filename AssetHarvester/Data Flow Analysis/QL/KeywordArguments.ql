 /**
 * @name Assets Passed in Driver Function as keyword arguments
 * @description Query for finding assets passed in the parameter of Driver functions as keyword arguments
 * @kind problem
 * @precision high
 * @id python/keyword-argument
 * @tags security
 * @problem.severity warning
 *       
 */

/*
 *  Captures the secret-asset pairs where the secrets and assets are present in a dictionary of another file and
 *  passed into the driver functions as keyword arguments.
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.TaintTracking
import semmle.python.frameworks.Aiomysql

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

class PymssqlCall extends DataFlow::Node {
  PymssqlCall() {
    this = API::moduleImport("pymssql").getMember("connect").getACall() or
    this = API::moduleImport("pymssql").getMember("Connection").getACall() or
    this = API::moduleImport("_mssql").getMember("connect").getACall() or
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

class SQLAlchemyCall extends DataFlow::Node {
  SQLAlchemyCall() { this = API::moduleImport("sqlalchemy").getMember("create_engine").getACall() }
}

class DriverCall extends DataFlow::Node {
  DriverCall() {
    this instanceof AiomysqlCall or
    this instanceof AiopgCall or
    this instanceof AsyncpgCall or
    this instanceof MysqlConnectorCall or
    this instanceof MysqlclientCall or
    this instanceof PsycopgCall or
    this instanceof PymssqlCall or
    this instanceof PymysqlCall or
    this instanceof PymongoCall or
    this instanceof PeeweePostgresqlDatabaseCall or
    this instanceof PeeweeMySQLDatabaseCall or
    this instanceof SQLAlchemyCall
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
        if this instanceof PymssqlCall
        then result = "sqlserver"
        else
          if this instanceof PymongoCall
          then result = "mongodb"
          else result = "ORM"
  }
}

class SqlDict extends Dict {
  DataFlow::CallCfgNode call;

  SqlDict() {
    exists(AssignStmt a, Name n |
      call instanceof DriverCall and
      n = call.asExpr().(Call).getKwargs()
    |
      a.getATarget().toString() = n.toString() and a.getValue() = this
    )
  }

  DataFlow::CallCfgNode getCall() { result = call }
}

class Host extends KeyValuePair {
  DataFlow::CallCfgNode call;

  Host() {
    exists(AssignStmt a, Name n |
      call instanceof DriverCall and
      n = call.asExpr().(Call).getKwargs()
    |
      a.getATarget().toString() = n.toString() and
      a.getValue().(Dict).getAnItem() = this and
      (
        this.getKey().(StrConst).getS() = "host" or
        this.getKey().(StrConst).getS() = "server"
      )
    )
  }

  DataFlow::CallCfgNode getCall() { result = call }
}

predicate getHost(SqlDict dict, string hostValue, string hostLocation) {
  if
    exists(Host host |
      dict.getCall() = host.getCall() and
      host = dict.getAnItem() and
      (
        host.getKey().(StrConst).getS() = "host" or
        host.getKey().(StrConst).getS() = "server"
      )
    )
  then
    exists(Host host |
      dict.getCall() = host.getCall() and
      host = dict.getAnItem() and
      (
        host.getKey().(StrConst).getS() = "host" or
        host.getKey().(StrConst).getS() = "server"
      )
    |
      hostValue = host.getValue().(StrConst).getS() and hostLocation = host.getLocation().toString()
    )
  else (
    hostValue = "Not Found" and hostLocation = "Not Found"
  )
}

class Port extends KeyValuePair {
  DataFlow::CallCfgNode call;

  Port() {
    exists(AssignStmt a, Name n |
      call instanceof DriverCall and
      n = call.asExpr().(Call).getKwargs()
    |
      a.getATarget().toString() = n.toString() and
      a.getValue().(Dict).getAnItem() = this and
      this.getKey().(StrConst).getS() = "port"
    )
  }

  DataFlow::CallCfgNode getCall() { result = call }
}

predicate getPort(SqlDict dict, string portValue, string portLocation) {
  if
    exists(Port port |
      dict.getCall() = port.getCall() and
      port = dict.getAnItem() and
      port.getKey().(StrConst).getS() = "port"
    )
  then
    exists(Port port |
      dict.getCall() = port.getCall() and
      port = dict.getAnItem() and
      port.getKey().(StrConst).getS() = "port"
    |
      (
        (
          portValue = port.getValue().(IntegerLiteral).getN() or
          portValue = port.getValue().(StrConst).getS()
        ) and
        portLocation = port.getLocation().toString()
      )
    )
  else (
    portValue = "Not Found" and portLocation = "Not Found"
  )
}

class DB extends KeyValuePair {
  DataFlow::CallCfgNode call;

  DB() {
    exists(AssignStmt a, Name n |
      call instanceof DriverCall and
      n = call.asExpr().(Call).getKwargs()
    |
      a.getATarget().toString() = n.toString() and
      a.getValue().(Dict).getAnItem() = this and
      (
        this.getKey().(StrConst).getS() = "db" or
        this.getKey().(StrConst).getS() = "database" or
        this.getKey().(StrConst).getS() = "dbname"
      )
    )
  }

  DataFlow::CallCfgNode getCall() { result = call }
}

predicate getDB(SqlDict dict, string dbValue, string dbLocation) {
  if
    exists(DB db |
      dict.getCall() = db.getCall() and
      db = dict.getAnItem() and
      (
        db.getKey().(StrConst).getS() = "db" or
        db.getKey().(StrConst).getS() = "database" or
        db.getKey().(StrConst).getS() = "dbname"
      )
    )
  then
    exists(DB db |
      dict.getCall() = db.getCall() and
      db = dict.getAnItem() and
      (
        db.getKey().(StrConst).getS() = "db" or
        db.getKey().(StrConst).getS() = "database" or
        db.getKey().(StrConst).getS() = "dbname"
      )
    |
      dbValue = db.getValue().(StrConst).getS() and dbLocation = db.getLocation().toString()
    )
  else (
    dbValue = "Not Found" and dbLocation = "Not Found"
  )
}

class User extends KeyValuePair {
  DataFlow::CallCfgNode call;

  User() {
    exists(AssignStmt a, Name n |
      call instanceof DriverCall and
      n = call.asExpr().(Call).getKwargs()
    |
      a.getATarget().toString() = n.toString() and
      a.getValue().(Dict).getAnItem() = this and
      (
        this.getKey().(StrConst).getS() = "user" or
        this.getKey().(StrConst).getS() = "username"
      )
    )
  }

  DataFlow::CallCfgNode getCall() { result = call }
}

predicate getUser(SqlDict dict, string userValue, string userLocation) {
  if
    exists(User user |
      dict.getCall() = user.getCall() and
      user = dict.getAnItem() and
      (
        user.getKey().(StrConst).getS() = "user" or
        user.getKey().(StrConst).getS() = "username"
      )
    )
  then
    exists(User user |
      dict.getCall() = user.getCall() and
      user = dict.getAnItem() and
      (
        user.getKey().(StrConst).getS() = "user" or
        user.getKey().(StrConst).getS() = "username"
      )
    |
      userValue = user.getValue().(StrConst).getS() and userLocation = user.getLocation().toString()
    )
  else (
    userValue = "Not Found" and userLocation = "Not Found"
  )
}

class Password extends KeyValuePair {
  DataFlow::CallCfgNode call;

  Password() {
    exists(AssignStmt a, Name n |
      call instanceof DriverCall and
      n = call.asExpr().(Call).getKwargs()
    |
      a.getATarget().toString() = n.toString() and
      a.getValue().(Dict).getAnItem() = this and
      (
        this.getKey().(StrConst).getS() = "password" or
        this.getKey().(StrConst).getS() = "passwd"
      )
    )
  }

  DataFlow::CallCfgNode getCall() { result = call }
}

predicate getPassword(SqlDict dict, string passwordValue, string passwordLocation) {
  if
    exists(Password password |
      dict.getCall() = password.getCall() and
      password = dict.getAnItem() and
      (
        password.getKey().(StrConst).getS() = "password" or
        password.getKey().(StrConst).getS() = "passwd"
      )
    )
  then
    exists(Password password |
      dict.getCall() = password.getCall() and
      password = dict.getAnItem() and
      (
        password.getKey().(StrConst).getS() = "password" or
        password.getKey().(StrConst).getS() = "passwd"
      )
    |
      passwordValue = password.getValue().(StrConst).getS() and
      passwordLocation = password.getLocation().toString()
    )
  else (
    passwordValue = "Not Found" and passwordLocation = "Not Found"
  )
}

from
  SqlDict dict, string hostValue, string hostLocation, string portValue, string portLocation,
  string dbValue, string dbLocation, string userValue, string userLocation, string passwordValue,
  string passwordLocation
where
  getHost(dict, hostValue, hostLocation) and
  getPort(dict, portValue, portLocation) and
  getDB(dict, dbValue, dbLocation) and
  getUser(dict, userValue, userLocation) and
  getPassword(dict, passwordValue, passwordLocation) and
  hostValue != "Not Found"
select dict.getCall().getLocation().toString() as callLocation, hostValue, hostLocation, portValue,
  portLocation, dbValue, dbLocation, userValue, userLocation, passwordValue, passwordLocation,
  dict.getCall().(DriverCall).getDBType() as dbType
