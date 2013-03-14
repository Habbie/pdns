/*
 *  PowerDNS LDAP Connector
 *  By PowerDNS.COM BV
 *  By Norbert Sendetzky <norbert@linuxnetworks.de> (2003-2007)
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */



#include <list>
#include <map>
#include <string>
#include <vector>
#include <stdexcept>
#include <inttypes.h>
#include <errno.h>
#include <lber.h>
#include <ldap.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif



#ifndef POWERLDAP_HH
#define POWERLDAP_HH

using std::list;
using std::map;
using std::string;
using std::vector;

class LdapAuthenticator;

class PowerLDAP
{
    LDAP* d_ld;
    string d_hosts;
    int d_port;
    bool d_tls;
    list<LDAPMessage*> m_results;
  
    const string getError( int rc = -1 );
    int waitResult( int msgid = LDAP_RES_ANY, int timeout = 0, LDAPMessage** result = NULL );
    void ensureConnect();
    
  public:
    typedef map<string, vector<string> > sentry_t;
    typedef vector<sentry_t> sresult_t;
  
    PowerLDAP( const string& hosts = "ldap://127.0.0.1/", uint16_t port = LDAP_PORT, bool tls = false );
    ~PowerLDAP();
  
    bool connect();
  
    void getOption( int option, int* value );
    void setOption( int option, int value );
  
    void bind( LdapAuthenticator *authenticator );
    void bind( const string& ldapbinddn = "", const string& ldapsecret = "", int method = LDAP_AUTH_SIMPLE, int timeout = 5 );
    void simpleBind( const string& ldapbinddn = "", const string& ldapsecret = "" );
    int search( const string& base, int scope, const string& filter, const char** attr = 0 );
  
    bool getSearchEntry( int msgid, sentry_t& entry, bool dn = false, int timeout = 5 );
    void getSearchResults( int msgid, sresult_t& result, bool dn = false, int timeout = 5 );
  
    static const string escape( const string& tobe );
};



#endif
