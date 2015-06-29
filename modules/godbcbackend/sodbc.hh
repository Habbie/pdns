// The Generic ODBC Backend
// By Michel Stol <michel@powerdns.com>

#ifndef SODBC_HH
#define SODBC_HH

#include <string>
#include <vector>

// The following line makes Bert puke every time he sees it.
//#define WINDOWS_LEAN_AND_MEAN
//#include <windows.h>
#include <sql.h>
#include <sqlext.h>

#include "pdns/backends/gsql/ssql.hh"

//! ODBC SSql implementation for use with the Generic ODBC Backend.
class SODBC : public SSql
{
private:  


  bool m_log;               //!< Should we log?
  bool m_busy;              //!< Are we busy executing a query?
  
  SQLHDBC   m_connection;   //!< Database connection handle. 
  SQLHENV   m_environment;  //!< Database environment handle  



public:
  //! Default constructor.
  /*!
  This constructor connects to an ODBC datasource and makes sure it's ready to use.

  \param database The database where the data is located (not used).
  \param dsn The ODBC DSN to use.
  \param username Username to use.
  \param password Password to use.
  */
  SODBC( 
    const std::string & dsn       = "PowerDNS", 
    const std::string & username  = "", 
    const std::string & password  = "" 
    );

  //! Destructor.
  virtual ~SODBC( void );

  // //! Executes a query.
  // int doQuery( const std::string & query );

  // //! Executes a query and stores the result.
  // int doQuery( const std::string & query, result_t & result );

  // //! Executes a command.
  // int doCommand( const std::string & command );

  // //! Escapes a SQL string.
  // std::string escape( const std::string & name );

  // //! Returns a row.
  // bool getRow( row_t & row );

  //! Sets the logging state.
  void setLog( bool state );

  SSqlStatement* prepare(const string& query, int nparams);
  void execute(const string& query);
  void startTransaction();
  void rollback();
  void commit();

  //! Returns an exception.
  SSqlException sPerrorException( const std::string & reason );

};


#endif // SODBC_HH
