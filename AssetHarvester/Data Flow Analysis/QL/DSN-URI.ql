/*
 *  Captures the secret-asset pairs where the secrets and assets are present in DSN/URI and passed directly to the first argument
 *  of the driver call and DSN URI is a string constant
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources
import semmle.python.Concepts
import semmle.python.objects.Instances

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

class PsycopgCall extends DataFlow::Node {
  PsycopgCall() {
    this = API::moduleImport("psycopg").getMember("connect").getACall() or
    this = API::moduleImport("psycopg2").getMember("connect").getACall()
  }
}

class PymongoCall extends DataFlow::Node {
  PymongoCall() {
    this = API::moduleImport("pymongo").getMember("connect").getACall() or
    this = API::moduleImport("pymongo").getMember("MongoClient").getACall()
  }
}

class PyodbcCall extends DataFlow::Node {
  PyodbcCall() { this = API::moduleImport("pyodbc").getMember("connect").getACall() }
}

class SQLAlchemyCall extends DataFlow::Node {
  SQLAlchemyCall() { this = API::moduleImport("sqlalchemy").getMember("create_engine").getACall() }
}

class CallSink extends DataFlow::Node {
  DataFlow::CallCfgNode call;

  CallSink() {
    (
      call instanceof AiopgCall or
      call instanceof AsyncpgCall or
      call instanceof PsycopgCall or
      call instanceof PymongoCall or
      call instanceof PyodbcCall or
      call instanceof SQLAlchemyCall
    ) and
    (
      this = call.getArgByName("dsn") or
      this = call.getArg(0) or
      this = call.getArgByName("conninfo") or
      this = call.getArgByName("url")
    )
  }

  DataFlow::CallCfgNode getCall() { result = call }

  string getDBType() {
    if
      this instanceof AiopgCall or
      this instanceof AsyncpgCall or
      this instanceof PsycopgCall
    then result = "postgresql"
    else
      if this instanceof PymongoCall
      then result = "mongodb"
      else result = "ORM"
  }
}

class DSNSource extends DataFlow::Node {
  DSNSource() { exists(StrConst str | this.asCfgNode().getNode() = str) }
}

module AssetFlowConfiguration implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof DSNSource }

  predicate isSink(DataFlow::Node sink) { sink instanceof CallSink }
}

module AssetFlow = TaintTracking::Global<AssetFlowConfiguration>;

from DataFlow::Node source, DataFlow::Node sink
where AssetFlow::flow(source, sink)
select sink.(CallSink).getCall().getLocation().toString() as callLocation,
  source.asCfgNode().pointsTo().toString() as dsn,
  source.asCfgNode().getLocation().toString() as dsnLocation, source.asCfgNode().getLocation().getStartColumn().toString() as dsnStartColumn, sink.(CallSink).getDBType() as dbType
