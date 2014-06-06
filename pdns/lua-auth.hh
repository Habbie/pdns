#ifndef PDNS_LUA_AUTH_HH
#define PDNS_LUA_AUTH_HH
#include "dns.hh"
#include "iputils.hh"
#include "dnspacket.hh"
#include "lua-pdns.hh"

class AuthLua : public PowerDNSLua
{
public:
  explicit AuthLua(const std::string& fname);
  // ~AuthLua();
  bool axfrfilter(const ComboAddress& remote, const string& zone, const DNSResourceRecord& in, vector<DNSResourceRecord>& out);
  DNSPacket* prequery(DNSPacket *p);
  int police(DNSPacket *req, DNSPacket *resp);

private:
  void registerLuaDNSPacket(void);
};

// FIXME: lua expects these to be in sync with RecursorBehaviour, perhaps just combine them?
namespace PolicyDecision { enum returnTypes { PASS=-1, DROP=-2, TRUNCATE=-3 }; };

#endif
