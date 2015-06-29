// The Generic ODBC Backend
// By Michel Stol <michel@powerdns.com>

#include "pdns/utility.hh"
#include <sstream>
#include "sodbc.hh"
#include <string.h>

static void testResult( SQLRETURN result, SQLSMALLINT type, SQLHANDLE handle, const std::string & message )
{
  cerr<<"result = "<<result<<endl;
  if ( result == SQL_SUCCESS || result == SQL_SUCCESS_WITH_INFO )
    return;

  ostringstream errmsg;

  errmsg << message << ": ";

  SQLINTEGER i = 0;
  SQLINTEGER native;
  SQLCHAR state[ 7 ];
  SQLCHAR text[256];
  SQLSMALLINT len;
  SQLRETURN ret;

  do
  {
    cerr<<"getting sql diag record "<<i<<endl;
    ret = SQLGetDiagRec(type, handle, ++i, state, &native, text,
    sizeof(text), &len );
    cerr<<"getdiagrec said "<<ret<<endl;
    if (SQL_SUCCEEDED(ret)) { cerr<<"got it"<<endl; 
      errmsg<<state<<i<<native<<text<<" "; 
    }
  }
  while( ret == SQL_SUCCESS );
  throw SSqlException( errmsg.str() );
}

class SODBCStatement: public SSqlStatement
{
public:
  SODBCStatement(const string& query, bool dolog, int nparams, SQLHDBC connection)
  {
    SQLRETURN result;

    d_query = query;
    // d_nparams = nparams;
    d_conn = connection;
    d_dolog = dolog;

    // Allocate statement handle.
    result = SQLAllocHandle( SQL_HANDLE_STMT, d_conn, &d_statement );
    testResult( result, SQL_HANDLE_DBC, d_conn, "Could not allocate a statement handle." );

    result = SQLPrepare(d_statement, (SQLCHAR *) query.c_str(), SQL_NTS);
    testResult( result, SQL_HANDLE_STMT, d_statement, "Could not prepare query." );
  } 

  SSqlStatement* bind(const string& name, bool value) { return this; }
  SSqlStatement* bind(const string& name, int value) { return this; }
  SSqlStatement* bind(const string& name, uint32_t value) { return this; }
  SSqlStatement* bind(const string& name, long value) { return this; }
  SSqlStatement* bind(const string& name, unsigned long value) { return this; }
  SSqlStatement* bind(const string& name, long long value) { return this; };
  SSqlStatement* bind(const string& name, unsigned long long value) { return this; }
  SSqlStatement* bind(const string& name, const std::string& value) { return this; }
  SSqlStatement* bindNull(const string& name) { return this; }


  SSqlStatement* execute()
  {
    SQLRETURN result;
    if (d_dolog) {
      // L<<Logger::Warning<<"Query: "<<d_query<<endl;
    }

    result = SQLExecute(d_statement);
    testResult( result, SQL_HANDLE_STMT, d_statement, "Could not execute query." );

    return this;
  }

  bool hasNextRow() { return false; }
  SSqlStatement* nextRow(row_t& row) { return this; }
  SSqlStatement* getResult(result_t& result) { return this; }
  SSqlStatement* reset() { return this; }
  const std::string& getQuery() { return d_query; }

private:
  string d_query;
  bool d_dolog;

  SQLHDBC d_conn;
  SQLHSTMT d_statement;    //!< Database statement handle.
};

// Constructor.
SODBC::SODBC( 
             const std::string & dsn,
             const std::string & username,
             const std::string & password 
            )
{
  SQLRETURN     result;

  // Allocate an environment handle.
  result = SQLAllocHandle( SQL_HANDLE_ENV, SQL_NULL_HANDLE, &m_environment );
  testResult( result, SQL_NULL_HANDLE, NULL, "Could not allocate an environment handle." );

  // Set ODBC version. (IEUW!)
  result = SQLSetEnvAttr( m_environment, SQL_ATTR_ODBC_VERSION, reinterpret_cast< void * >( SQL_OV_ODBC3 ), 0 );
  testResult( result, SQL_HANDLE_ENV, m_environment, "Could not set the ODBC version." );

  // Allocate connection handle.
  result = SQLAllocHandle( SQL_HANDLE_DBC, m_environment, &m_connection );
  testResult( result, SQL_HANDLE_ENV, m_environment, "Could not allocate a connection handle." );

  // Connect to the database.
  char *l_dsn       = strdup( dsn.c_str());
  char *l_username  = strdup( username.c_str());
  char *l_password  = strdup( password.c_str());

  result = SQLConnect( m_connection,
    reinterpret_cast< SQLTCHAR * >( l_dsn ), dsn.length(),
    reinterpret_cast< SQLTCHAR * >( l_username ), username.length(),
    reinterpret_cast< SQLTCHAR * >( l_password ), password.length());

  free( l_dsn );
  free( l_username );
  free( l_password );

  testResult( result, SQL_HANDLE_DBC, m_connection, "Could not connect to ODBC datasource." );


  m_busy  = false;
  m_log   = false;
}


// Destructor.
SODBC::~SODBC( void )
{
  // Disconnect from database and free all used resources.
  // SQLFreeHandle( SQL_HANDLE_STMT, m_statement );

  SQLDisconnect( m_connection );

  SQLFreeHandle( SQL_HANDLE_DBC, m_connection );
  SQLFreeHandle( SQL_HANDLE_ENV, m_environment );

  // Free all allocated column memory.
  // for ( int i = 0; i < m_columnInfo.size(); i++ )
  // {
  //   if ( m_columnInfo[ i ].m_pData )
  //     delete m_columnInfo[ i ].m_pData;
  // }
}


// Executes a query.
// int SODBC::doQuery( const std::string & query )
// {
//   SQLRETURN   result;
//   char        *tmp;
  
//   if ( m_busy )
//     throw SSqlException( "Tried to execute another query while being busy." );

//   tmp = strdup( query.c_str());

//   // Execute query.
//   result = SQLExecDirect( m_statement, reinterpret_cast< SQLTCHAR * >( tmp ), query.length());
//   free( tmp );

//   testResult( result, "Could not execute query." );

//   // We are now busy.
//   m_busy = true;

//   // Determine the number of columns.
//   SQLSMALLINT numColumns;
//   SQLNumResultCols( m_statement, &numColumns );

//   if ( numColumns == 0 )
//     throw SSqlException( "Could not determine the number of columns." );

//   // Fill m_columnInfo.
//   m_columnInfo.clear();

//   column_t    column;
//   SQLSMALLINT nullable;
//   SQLSMALLINT type;

//   for ( SQLSMALLINT i = 1; i <= numColumns; i++ )
//   {
//     SQLDescribeCol( m_statement, i, NULL, 0, NULL, &type, &column.m_size, NULL, &nullable );

//     if ( nullable == SQL_NULLABLE )
//       column.m_canBeNull = true;
//     else
//       column.m_canBeNull = false;

//     // Allocate memory.
//     switch ( type )
//     {
//     case SQL_CHAR:
//     case SQL_VARCHAR:
//     case SQL_LONGVARCHAR:
//       column.m_type   = SQL_C_CHAR;
//       column.m_pData  = new SQLCHAR[ column.m_size ];
//       break;

//     case SQL_SMALLINT:
//     case SQL_INTEGER:
//       column.m_type  = SQL_C_SLONG;
//       column.m_size  = sizeof( long int );
//       column.m_pData = new long int;
//       break;

//     case SQL_REAL:
//     case SQL_FLOAT:
//     case SQL_DOUBLE:
//       column.m_type   = SQL_C_DOUBLE;
//       column.m_size   = sizeof( double );
//       column.m_pData  = new double;
//       break;

//     default:
//       column.m_pData = NULL;

//     }

//     m_columnInfo.push_back( column );
//   }

//   return 0;
// }


// Executes a query.
// int SODBC::doQuery( const std::string & query, result_t & result )
// {
//   result.clear();

//   doQuery( query );

//   row_t row;
//   while ( getRow( row ))
//     result.push_back( row );

//   return result.size();
// }


// Executes a command.
void SODBC::execute( const std::string & command )
{
  SQLRETURN   result;
  SODBCStatement stmt(command, false, 0, &m_connection);

  stmt.execute()->reset();
}

// Escapes a SQL string.
// std::string SODBC::escape( const std::string & name )
// {
//   std::string a;

//   for( std::string::const_iterator i = name.begin(); i != name.end(); ++i ) 
//   {
//     if( *i == '\'' || *i == '\\' )
//       a += '\\';
//     a += *i;
//   }

//   return a;
// }


// Returns the content of a row.
// bool SODBC::getRow( row_t & row )
// {
//   SQLRETURN result;

//   row.clear();

//   result = SQLFetch( m_statement );
//   if ( result == SQL_SUCCESS || result == SQL_SUCCESS_WITH_INFO )
//   {
//     // We've got a data row, now lets get the results.
//     SQLLEN len;
//     for ( int i = 0; i < m_columnInfo.size(); i++ )
//     {
//       if ( m_columnInfo[ i ].m_pData == NULL )
//         continue;

//       // Clear buffer.
//       memset( m_columnInfo[ i ].m_pData, 0, m_columnInfo[ i ].m_size );

//       SQLGetData( m_statement, i + 1, m_columnInfo[ i ].m_type, m_columnInfo[ i ].m_pData, m_columnInfo[ i ].m_size, &len );

//       if ( len == SQL_NULL_DATA )
//       {
//         // Column is NULL, so we can skip the converting part.
//         row.push_back( "" );
//         continue;
//       }

//       // Convert the data into strings.
//       std::ostringstream str;

//       switch ( m_columnInfo[ i ].m_type )
//       {
//       case SQL_C_CHAR:
//         row.push_back( reinterpret_cast< char * >( m_columnInfo[ i ].m_pData ));
//         break;

//       case SQL_C_SSHORT:
//       case SQL_C_SLONG:
//         str << *( reinterpret_cast< long * >( m_columnInfo[ i ].m_pData ));
//         row.push_back( str.str());

//         break;

//       case SQL_C_DOUBLE:
//         str << *( reinterpret_cast< double * >( m_columnInfo[ i ].m_pData ));
//         row.push_back( str.str());

//         break;

//       default:
//         // Eh?
//         row.push_back( "" );

//       }
//     }

//     // Done!
//     return true;
//   }

//   // No further results, or error.
//   m_busy = false;

//   // Free all allocated column memory.
//   for ( int i = 0; i < m_columnInfo.size(); i++ )
//   {
//     if ( m_columnInfo[ i ].m_pData )
//       delete m_columnInfo[ i ].m_pData;
//   }

//   SQLFreeStmt( m_statement, SQL_CLOSE );

//   return false;
// }


// Sets the log state.
void SODBC::setLog( bool state )
{
  m_log = state;
}


// Returns an exception.
SSqlException SODBC::sPerrorException( const std::string & reason )
{
  return SSqlException( reason );
}


SSqlStatement* SODBC::prepare(const string& query, int nparams)
{
  return new SODBCStatement(query, true, nparams, m_connection);
}



  void SODBC::startTransaction() {}
  void SODBC::commit() {}
  void SODBC::rollback() {}
