/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include "dnsdist.hh"
#include "sstuff.hh"
#include "ext/json11/json11.hpp"
#include "ext/incbin/incbin.h"
#include "dolog.hh"
#include <thread>
#include "threadname.hh"
#include <sstream>
#include <yahttp/yahttp.hpp>
#include "namespaces.hh"
#include <sys/time.h>
#include <sys/resource.h>
#include "ext/incbin/incbin.h"
#include "htmlfiles.h"
#include "base64.hh"
#include "gettime.hh"
#include  <boost/format.hpp>

bool g_apiReadWrite{false};
WebserverConfig g_webserverConfig;
std::string g_apiConfigDirectory;

static bool apiWriteConfigFile(const string& filebasename, const string& content)
{
  if (!g_apiReadWrite) {
    errlog("Not writing content to %s since the API is read-only", filebasename);
    return false;
  }

  if (g_apiConfigDirectory.empty()) {
    vinfolog("Not writing content to %s since the API configuration directory is not set", filebasename);
    return false;
  }

  string filename = g_apiConfigDirectory + "/" + filebasename + ".conf";
  ofstream ofconf(filename.c_str());
  if (!ofconf) {
    errlog("Could not open configuration fragment file '%s' for writing: %s", filename, stringerror());
    return false;
  }
  ofconf << "-- Generated by the REST API, DO NOT EDIT" << endl;
  ofconf << content << endl;
  ofconf.close();
  return true;
}

static void apiSaveACL(const NetmaskGroup& nmg)
{
  vector<string> vec;
  nmg.toStringVector(&vec);

  string acl;
  for(const auto& s : vec) {
    if (!acl.empty()) {
      acl += ", ";
    }
    acl += "\"" + s + "\"";
  }

  string content = "setACL({" + acl + "})";
  apiWriteConfigFile("acl", content);
}

static bool checkAPIKey(const YaHTTP::Request& req, const string& expectedApiKey)
{
  if (expectedApiKey.empty()) {
    return false;
  }

  const auto header = req.headers.find("x-api-key");
  if (header != req.headers.end()) {
    return (header->second == expectedApiKey);
  }

  return false;
}

static bool checkWebPassword(const YaHTTP::Request& req, const string &expected_password)
{
  static const char basicStr[] = "basic ";

  const auto header = req.headers.find("authorization");

  if (header != req.headers.end() && toLower(header->second).find(basicStr) == 0) {
    string cookie = header->second.substr(sizeof(basicStr) - 1);

    string plain;
    B64Decode(cookie, plain);

    vector<string> cparts;
    stringtok(cparts, plain, ":");

    if (cparts.size() == 2) {
      return cparts[1] == expected_password;
    }
  }

  return false;
}

static bool isAnAPIRequest(const YaHTTP::Request& req)
{
  return req.url.path.find("/api/") == 0;
}

static bool isAnAPIRequestAllowedWithWebAuth(const YaHTTP::Request& req)
{
  return req.url.path == "/api/v1/servers/localhost";
}

static bool isAStatsRequest(const YaHTTP::Request& req)
{
  return req.url.path == "/jsonstat" || req.url.path == "/metrics";
}

static bool compareAuthorization(const YaHTTP::Request& req)
{
  std::lock_guard<std::mutex> lock(g_webserverConfig.lock);

  if (isAnAPIRequest(req)) {
    /* Access to the API requires a valid API key */
    if (checkAPIKey(req, g_webserverConfig.apiKey)) {
      return true;
    }

    return isAnAPIRequestAllowedWithWebAuth(req) && checkWebPassword(req, g_webserverConfig.password);
  }

  if (isAStatsRequest(req)) {
    /* Access to the stats is allowed for both API and Web users */
    return checkAPIKey(req, g_webserverConfig.apiKey) || checkWebPassword(req, g_webserverConfig.password);
  }

  return checkWebPassword(req, g_webserverConfig.password);
}

static bool isMethodAllowed(const YaHTTP::Request& req)
{
  if (req.method == "GET") {
    return true;
  }
  if (req.method == "PUT" && g_apiReadWrite) {
    if (req.url.path == "/api/v1/servers/localhost/config/allow-from") {
      return true;
    }
  }
  return false;
}

static void handleCORS(const YaHTTP::Request& req, YaHTTP::Response& resp)
{
  const auto origin = req.headers.find("Origin");
  if (origin != req.headers.end()) {
    if (req.method == "OPTIONS") {
      /* Pre-flight request */
      if (g_apiReadWrite) {
        resp.headers["Access-Control-Allow-Methods"] = "GET, PUT";
      }
      else {
        resp.headers["Access-Control-Allow-Methods"] = "GET";
      }
      resp.headers["Access-Control-Allow-Headers"] = "Authorization, X-API-Key";
    }

    resp.headers["Access-Control-Allow-Origin"] = origin->second;

    if (isAStatsRequest(req) || isAnAPIRequestAllowedWithWebAuth(req)) {
      resp.headers["Access-Control-Allow-Credentials"] = "true";
    }
  }
}

static void addSecurityHeaders(YaHTTP::Response& resp, const boost::optional<std::map<std::string, std::string> >& customHeaders)
{
  static const std::vector<std::pair<std::string, std::string> > headers = {
    { "X-Content-Type-Options", "nosniff" },
    { "X-Frame-Options", "deny" },
    { "X-Permitted-Cross-Domain-Policies", "none" },
    { "X-XSS-Protection", "1; mode=block" },
    { "Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'" },
  };

  for (const auto& h : headers) {
    if (customHeaders) {
      const auto& custom = customHeaders->find(h.first);
      if (custom != customHeaders->end()) {
        continue;
      }
    }
    resp.headers[h.first] = h.second;
  }
}

static void addCustomHeaders(YaHTTP::Response& resp, const boost::optional<std::map<std::string, std::string> >& customHeaders)
{
  if (!customHeaders)
    return;

  for (const auto& c : *customHeaders) {
    if (!c.second.empty()) {
      resp.headers[c.first] = c.second;
    }
  }
}

template<typename T>
static json11::Json::array someResponseRulesToJson(GlobalStateHolder<vector<T>>* someResponseRules)
{
  using namespace json11;
  Json::array responseRules;
  int num=0;
  auto localResponseRules = someResponseRules->getLocal();
  for(const auto& a : *localResponseRules) {
    Json::object rule{
      {"id", num++},
      {"creationOrder", (double)a.d_creationOrder},
      {"uuid", boost::uuids::to_string(a.d_id)},
      {"matches", (double)a.d_rule->d_matches},
      {"rule", a.d_rule->toString()},
      {"action", a.d_action->toString()},
    };
    responseRules.push_back(rule);
  }
  return responseRules;
}

static void connectionThread(int sock, ComboAddress remote)
{
  setThreadName("dnsdist/webConn");

  using namespace json11;
  vinfolog("Webserver handling connection from %s", remote.toStringWithPort());

  try {
    YaHTTP::AsyncRequestLoader yarl;
    YaHTTP::Request req;
    bool finished = false;

    yarl.initialize(&req);
    while(!finished) {
      int bytes;
      char buf[1024];
      bytes = read(sock, buf, sizeof(buf));
      if (bytes > 0) {
        string data = string(buf, bytes);
        finished = yarl.feed(data);
      } else {
        // read error OR EOF
        break;
      }
    }
    yarl.finalize();

    string command=req.getvars["command"];

    req.getvars.erase("_"); // jQuery cache buster

    YaHTTP::Response resp;
    resp.version = req.version;
    const string charset = "; charset=utf-8";

    {
      std::lock_guard<std::mutex> lock(g_webserverConfig.lock);

      addCustomHeaders(resp, g_webserverConfig.customHeaders);
      addSecurityHeaders(resp, g_webserverConfig.customHeaders);
    }
    /* indicate that the connection will be closed after completion of the response */
    resp.headers["Connection"] = "close";

    /* no need to send back the API key if any */
    resp.headers.erase("X-API-Key");

    if(req.method == "OPTIONS") {
      /* the OPTIONS method should not require auth, otherwise it breaks CORS */
      handleCORS(req, resp);
      resp.status=200;
    }
    else if (!compareAuthorization(req)) {
      YaHTTP::strstr_map_t::iterator header = req.headers.find("authorization");
      if (header != req.headers.end())
        errlog("HTTP Request \"%s\" from %s: Web Authentication failed", req.url.path, remote.toStringWithPort());
      resp.status=401;
      resp.body="<h1>Unauthorized</h1>";
      resp.headers["WWW-Authenticate"] = "basic realm=\"PowerDNS\"";

    }
    else if(!isMethodAllowed(req)) {
      resp.status=405;
    }
    else if(req.url.path=="/jsonstat") {
      handleCORS(req, resp);
      resp.status=200;

      if(command=="stats") {
        auto obj=Json::object {
          { "packetcache-hits", 0},
          { "packetcache-misses", 0},
          { "over-capacity-drops", 0 },
          { "too-old-drops", 0 },
          { "server-policy", g_policy.getLocal()->name}
        };

        for(const auto& e : g_stats.entries) {
          if (e.first == "special-memory-usage")
            continue; // Too expensive for get-all
          if(const auto& val = boost::get<DNSDistStats::stat_t*>(&e.second))
            obj.insert({e.first, (double)(*val)->load()});
          else if (const auto& dval = boost::get<double*>(&e.second))
            obj.insert({e.first, (**dval)});
          else
            obj.insert({e.first, (double)(*boost::get<DNSDistStats::statfunction_t>(&e.second))(e.first)});
        }
        Json my_json = obj;
        resp.body=my_json.dump();
        resp.headers["Content-Type"] = "application/json";
      }
      else if(command=="dynblocklist") {
        Json::object obj;
        auto nmg = g_dynblockNMG.getLocal();
        struct timespec now;
        gettime(&now);
        for(const auto& e: *nmg) {
          if(now < e->second.until ) {
            Json::object thing{
              {"reason", e->second.reason},
              {"seconds", (double)(e->second.until.tv_sec - now.tv_sec)},
              {"blocks", (double)e->second.blocks},
              {"action", DNSAction::typeToString(e->second.action != DNSAction::Action::None ? e->second.action : g_dynBlockAction) },
              {"warning", e->second.warning }
            };
            obj.insert({e->first.toString(), thing});
          }
        }

        auto smt = g_dynblockSMT.getLocal();
        smt->visit([&now,&obj](const SuffixMatchTree<DynBlock>& node) {
            if(now <node.d_value.until) {
              string dom("empty");
              if(!node.d_value.domain.empty())
                dom = node.d_value.domain.toString();
              Json::object thing{
                {"reason", node.d_value.reason},
                {"seconds", (double)(node.d_value.until.tv_sec - now.tv_sec)},
                {"blocks", (double)node.d_value.blocks},
                {"action", DNSAction::typeToString(node.d_value.action != DNSAction::Action::None ? node.d_value.action : g_dynBlockAction) }
              };
              obj.insert({dom, thing});
          }
        });



        Json my_json = obj;
        resp.body=my_json.dump();
        resp.headers["Content-Type"] = "application/json";
      }
      else if(command=="ebpfblocklist") {
        Json::object obj;
#ifdef HAVE_EBPF
        struct timespec now;
        gettime(&now);
        for (const auto& dynbpf : g_dynBPFFilters) {
          std::vector<std::tuple<ComboAddress, uint64_t, struct timespec> > addrStats = dynbpf->getAddrStats();
          for (const auto& entry : addrStats) {
            Json::object thing
            {
              {"seconds", (double)(std::get<2>(entry).tv_sec - now.tv_sec)},
              {"blocks", (double)(std::get<1>(entry))}
            };
            obj.insert({std::get<0>(entry).toString(), thing });
          }
        }
#endif /* HAVE_EBPF */
        Json my_json = obj;
        resp.body=my_json.dump();
        resp.headers["Content-Type"] = "application/json";
      }
      else {
        resp.status=404;
      }
    }
    else if (req.url.path == "/metrics") {
        handleCORS(req, resp);
        resp.status = 200;

        std::ostringstream output;
        for (const auto& e : g_stats.entries) {
          if (e.first == "special-memory-usage")
            continue; // Too expensive for get-all
          std::string metricName = std::get<0>(e);

          // Prometheus suggest using '_' instead of '-'
          std::string prometheusMetricName = "dnsdist_" + boost::replace_all_copy(metricName, "-", "_");

          MetricDefinition metricDetails;

          if (!g_metricDefinitions.getMetricDetails(metricName, metricDetails)) {
              vinfolog("Do not have metric details for %s", metricName);
              continue;
          }

          std::string prometheusTypeName = g_metricDefinitions.getPrometheusStringMetricType(metricDetails.prometheusType);

          if (prometheusTypeName == "") {
              vinfolog("Unknown Prometheus type for %s", metricName);
              continue;
          }

          // for these we have the help and types encoded in the sources:
          output << "# HELP " << prometheusMetricName << " " << metricDetails.description    << "\n";
          output << "# TYPE " << prometheusMetricName << " " << prometheusTypeName << "\n";
          output << prometheusMetricName << " ";

          if (const auto& val = boost::get<DNSDistStats::stat_t*>(&std::get<1>(e)))
            output << (*val)->load();
          else if (const auto& dval = boost::get<double*>(&std::get<1>(e)))
            output << **dval;
          else
            output << (*boost::get<DNSDistStats::statfunction_t>(&std::get<1>(e)))(std::get<0>(e));

          output << "\n";
        }

        auto states = g_dstates.getLocal();
        const string statesbase = "dnsdist_server_";

        output << "# HELP " << statesbase << "queries "     << "Amount of queries relayed to server"                               << "\n";
        output << "# TYPE " << statesbase << "queries "     << "counter"                                                           << "\n";
        output << "# HELP " << statesbase << "drops "       << "Amount of queries not answered by server"                          << "\n";
        output << "# TYPE " << statesbase << "drops "       << "counter"                                                           << "\n";
        output << "# HELP " << statesbase << "latency "     << "Server's latency when answering questions in miliseconds"          << "\n";
        output << "# TYPE " << statesbase << "latency "     << "gauge"                                                             << "\n";
        output << "# HELP " << statesbase << "senderrors "  << "Total number of OS snd errors while relaying queries"              << "\n";
        output << "# TYPE " << statesbase << "senderrors "  << "counter"                                                           << "\n";
        output << "# HELP " << statesbase << "outstanding " << "Current number of queries that are waiting for a backend response" << "\n";
        output << "# TYPE " << statesbase << "outstanding " << "gauge"                                                             << "\n";
        output << "# HELP " << statesbase << "order "       << "The order in which this server is picked"                          << "\n";
        output << "# TYPE " << statesbase << "order "       << "gauge"                                                             << "\n";
        output << "# HELP " << statesbase << "weight "      << "The weight within the order in which this server is picked"        << "\n";
        output << "# TYPE " << statesbase << "weight "      << "gauge"                                                             << "\n";

        for (const auto& state : *states) {
          string serverName;

          if (state->name.empty())
              serverName = state->remote.toStringWithPort();
          else
              serverName = state->getName();

          boost::replace_all(serverName, ".", "_");

          const std::string label = boost::str(boost::format("{server=\"%1%\",address=\"%2%\"}")
            % serverName % state->remote.toStringWithPort());

          output << statesbase << "queries"     << label << " " << state->queries.load()     << "\n";
          output << statesbase << "drops"       << label << " " << state->reuseds.load()     << "\n";
          output << statesbase << "latency"     << label << " " << state->latencyUsec/1000.0 << "\n";
          output << statesbase << "senderrors"  << label << " " << state->sendErrors.load()  << "\n";
          output << statesbase << "outstanding" << label << " " << state->outstanding.load() << "\n";
          output << statesbase << "order"       << label << " " << state->order              << "\n";
          output << statesbase << "weight"      << label << " " << state->weight             << "\n";
        }

        for (const auto& front : g_frontends) {
          if (front->udpFD == -1 && front->tcpFD == -1)
            continue;

          string frontName = front->local.toString() + ":" + std::to_string(front->local.getPort());
          string proto = (front->udpFD >= 0 ? "udp" : "tcp");

          output << "dnsdist_frontend_queries{frontend=\"" << frontName << "\",proto=\"" << proto
              << "\"} " << front->queries.load() << "\n";
        }

        auto localPools = g_pools.getLocal();
        const string cachebase = "dnsdist_pool_";

        for (const auto& entry : *localPools) {
          string poolName = entry.first;

          if (poolName.empty()) {
            poolName = "_default_";
          }
          const string label = "{pool=\"" + poolName + "\"}";
          const std::shared_ptr<ServerPool> pool = entry.second;
          output << "dnsdist_pool_servers" << label << " " << pool->countServers(false) << "\n";
          output << "dnsdist_pool_active_servers" << label << " " << pool->countServers(true) << "\n";

          if (pool->packetCache != nullptr) {
            const auto& cache = pool->packetCache;

            output << cachebase << "cache_size"              <<label << " " << cache->getMaxEntries()       << "\n";
            output << cachebase << "cache_entries"           <<label << " " << cache->getEntriesCount()     << "\n";
            output << cachebase << "cache_hits"              <<label << " " << cache->getHits()             << "\n";
            output << cachebase << "cache_misses"            <<label << " " << cache->getMisses()           << "\n";
            output << cachebase << "cache_deferred_inserts"  <<label << " " << cache->getDeferredInserts()  << "\n";
            output << cachebase << "cache_deferred_lookups"  <<label << " " << cache->getDeferredLookups()  << "\n";
            output << cachebase << "cache_lookup_collisions" <<label << " " << cache->getLookupCollisions() << "\n";
            output << cachebase << "cache_insert_collisions" <<label << " " << cache->getInsertCollisions() << "\n";
            output << cachebase << "cache_ttl_too_shorts"    <<label << " " << cache->getTTLTooShorts()     << "\n";
          }
        }

        resp.body = output.str();
        resp.headers["Content-Type"] = "text/plain";
    }

    else if(req.url.path=="/api/v1/servers/localhost") {
      handleCORS(req, resp);
      resp.status=200;

      Json::array servers;
      auto localServers = g_dstates.getLocal();
      int num=0;
      for(const auto& a : *localServers) {
	string status;
	if(a->availability == DownstreamState::Availability::Up)
	  status = "UP";
	else if(a->availability == DownstreamState::Availability::Down)
	  status = "DOWN";
	else
	  status = (a->upStatus ? "up" : "down");

	Json::array pools;
	for(const auto& p: a->pools)
	  pools.push_back(p);

	Json::object server{
	  {"id", num++},
	  {"name", a->name},
          {"address", a->remote.toStringWithPort()},
          {"state", status},
          {"qps", (double)a->queryLoad},
          {"qpsLimit", (double)a->qps.getRate()},
          {"outstanding", (double)a->outstanding},
          {"reuseds", (double)a->reuseds},
          {"weight", (double)a->weight},
          {"order", (double)a->order},
          {"pools", pools},
          {"latency", (double)(a->latencyUsec/1000.0)},
          {"queries", (double)a->queries},
          {"sendErrors", (double)a->sendErrors},
          {"dropRate", (double)a->dropRate}
        };

        /* sending a latency for a DOWN server doesn't make sense */
        if (a->availability == DownstreamState::Availability::Down) {
          server["latency"] = nullptr;
        }

	servers.push_back(server);
      }

      Json::array frontends;
      num=0;
      for(const auto& front : g_frontends) {
        if (front->udpFD == -1 && front->tcpFD == -1)
          continue;
        Json::object frontend{
          { "id", num++ },
          { "address", front->local.toStringWithPort() },
          { "udp", front->udpFD >= 0 },
          { "tcp", front->tcpFD >= 0 },
          { "queries", (double) front->queries.load() }
        };
        frontends.push_back(frontend);
      }

      Json::array pools;
      auto localPools = g_pools.getLocal();
      num=0;
      for(const auto& pool : *localPools) {
        const auto& cache = pool.second->packetCache;
        Json::object entry {
          { "id", num++ },
          { "name", pool.first },
          { "serversCount", (double) pool.second->countServers(false) },
          { "cacheSize", (double) (cache ? cache->getMaxEntries() : 0) },
          { "cacheEntries", (double) (cache ? cache->getEntriesCount() : 0) },
          { "cacheHits", (double) (cache ? cache->getHits() : 0) },
          { "cacheMisses", (double) (cache ? cache->getMisses() : 0) },
          { "cacheDeferredInserts", (double) (cache ? cache->getDeferredInserts() : 0) },
          { "cacheDeferredLookups", (double) (cache ? cache->getDeferredLookups() : 0) },
          { "cacheLookupCollisions", (double) (cache ? cache->getLookupCollisions() : 0) },
          { "cacheInsertCollisions", (double) (cache ? cache->getInsertCollisions() : 0) },
          { "cacheTTLTooShorts", (double) (cache ? cache->getTTLTooShorts() : 0) }
        };
        pools.push_back(entry);
      }

      Json::array rules;
      auto localRules = g_rulactions.getLocal();
      num=0;
      for(const auto& a : *localRules) {
	Json::object rule{
          {"id", num++},
          {"creationOrder", (double)a.d_creationOrder},
          {"uuid", boost::uuids::to_string(a.d_id)},
          {"matches", (double)a.d_rule->d_matches},
          {"rule", a.d_rule->toString()},
          {"action", a.d_action->toString()},
          {"action-stats", a.d_action->getStats()}
        };
	rules.push_back(rule);
      }

      auto responseRules = someResponseRulesToJson(&g_resprulactions);
      auto cacheHitResponseRules = someResponseRulesToJson(&g_cachehitresprulactions);
      auto selfAnsweredResponseRules = someResponseRulesToJson(&g_selfansweredresprulactions);

      string acl;

      vector<string> vec;
      g_ACL.getLocal()->toStringVector(&vec);

      for(const auto& s : vec) {
        if(!acl.empty()) acl += ", ";
        acl+=s;
      }
      string localaddresses;
      for(const auto& loc : g_locals) {
        if(!localaddresses.empty()) localaddresses += ", ";
        localaddresses += std::get<0>(loc).toStringWithPort();
      }

      Json my_json = Json::object {
        { "daemon_type", "dnsdist" },
        { "version", VERSION},
        { "servers", servers},
        { "frontends", frontends },
        { "pools", pools },
        { "rules", rules},
        { "response-rules", responseRules},
        { "cache-hit-response-rules", cacheHitResponseRules},
        { "self-answered-response-rules", selfAnsweredResponseRules},
        { "acl", acl},
        { "local", localaddresses}
      };
      resp.headers["Content-Type"] = "application/json";
      resp.body=my_json.dump();
    }
    else if(req.url.path=="/api/v1/servers/localhost/statistics") {
      handleCORS(req, resp);
      resp.status=200;

      Json::array doc;
      for(const auto& item : g_stats.entries) {
        if (item.first == "special-memory-usage")
          continue; // Too expensive for get-all

        if(const auto& val = boost::get<DNSDistStats::stat_t*>(&item.second)) {
          doc.push_back(Json::object {
              { "type", "StatisticItem" },
              { "name", item.first },
              { "value", (double)(*val)->load() }
            });
        }
        else if (const auto& dval = boost::get<double*>(&item.second)) {
          doc.push_back(Json::object {
              { "type", "StatisticItem" },
              { "name", item.first },
              { "value", (**dval) }
            });
        }
        else {
          doc.push_back(Json::object {
              { "type", "StatisticItem" },
              { "name", item.first },
              { "value", (double)(*boost::get<DNSDistStats::statfunction_t>(&item.second))(item.first) }
            });
        }
      }
      Json my_json = doc;
      resp.body=my_json.dump();
      resp.headers["Content-Type"] = "application/json";
    }
    else if(req.url.path=="/api/v1/servers/localhost/config") {
      handleCORS(req, resp);
      resp.status=200;

      Json::array doc;
      typedef boost::variant<bool, double, std::string> configentry_t;
      std::vector<std::pair<std::string, configentry_t> > configEntries {
        { "acl", g_ACL.getLocal()->toString() },
        { "allow-empty-response", g_allowEmptyResponse },
        { "control-socket", g_serverControl.toStringWithPort() },
        { "ecs-override", g_ECSOverride },
        { "ecs-source-prefix-v4", (double) g_ECSSourcePrefixV4 },
        { "ecs-source-prefix-v6", (double)  g_ECSSourcePrefixV6 },
        { "fixup-case", g_fixupCase },
        { "max-outstanding", (double) g_maxOutstanding },
        { "server-policy", g_policy.getLocal()->name },
        { "stale-cache-entries-ttl", (double) g_staleCacheEntriesTTL },
        { "tcp-recv-timeout", (double) g_tcpRecvTimeout },
        { "tcp-send-timeout", (double) g_tcpSendTimeout },
        { "truncate-tc", g_truncateTC },
        { "verbose", g_verbose },
        { "verbose-health-checks", g_verboseHealthChecks }
      };
      for(const auto& item : configEntries) {
        if (const auto& bval = boost::get<bool>(&item.second)) {
          doc.push_back(Json::object {
              { "type", "ConfigSetting" },
              { "name", item.first },
              { "value", *bval }
          });
        }
        else if (const auto& sval = boost::get<string>(&item.second)) {
          doc.push_back(Json::object {
              { "type", "ConfigSetting" },
              { "name", item.first },
              { "value", *sval }
          });
        }
        else if (const auto& dval = boost::get<double>(&item.second)) {
          doc.push_back(Json::object {
              { "type", "ConfigSetting" },
              { "name", item.first },
              { "value", *dval }
          });
        }
      }
      Json my_json = doc;
      resp.body=my_json.dump();
      resp.headers["Content-Type"] = "application/json";
    }
    else if(req.url.path=="/api/v1/servers/localhost/config/allow-from") {
      handleCORS(req, resp);

      resp.headers["Content-Type"] = "application/json";
      resp.status=200;

      if (req.method == "PUT") {
        std::string err;
        Json doc = Json::parse(req.body, err);

        if (!doc.is_null()) {
          NetmaskGroup nmg;
          auto aclList = doc["value"];
          if (aclList.is_array()) {

            for (auto value : aclList.array_items()) {
              try {
                nmg.addMask(value.string_value());
              } catch (NetmaskException &e) {
                resp.status = 400;
                break;
              }
            }

            if (resp.status == 200) {
              infolog("Updating the ACL via the API to %s", nmg.toString());
              g_ACL.setState(nmg);
              apiSaveACL(nmg);
            }
          }
          else {
            resp.status = 400;
          }
        }
        else {
          resp.status = 400;
        }
      }
      if (resp.status == 200) {
        Json::array acl;
        vector<string> vec;
        g_ACL.getLocal()->toStringVector(&vec);

        for(const auto& s : vec) {
          acl.push_back(s);
        }

        Json::object obj{
          { "type", "ConfigSetting" },
          { "name", "allow-from" },
          { "value", acl }
        };
        Json my_json = obj;
        resp.body=my_json.dump();
      }
    }
    else if(!req.url.path.empty() && g_urlmap.count(req.url.path.c_str()+1)) {
      resp.body.assign(g_urlmap[req.url.path.c_str()+1]);
      vector<string> parts;
      stringtok(parts, req.url.path, ".");
      if(parts.back() == "html")
        resp.headers["Content-Type"] = "text/html" + charset;
      else if(parts.back() == "css")
        resp.headers["Content-Type"] = "text/css" + charset;
      else if(parts.back() == "js")
        resp.headers["Content-Type"] = "application/javascript" + charset;
      else if(parts.back() == "png")
        resp.headers["Content-Type"] = "image/png";
      resp.status=200;
    }
    else if(req.url.path=="/") {
      resp.body.assign(g_urlmap["index.html"]);
      resp.headers["Content-Type"] = "text/html" + charset;
      resp.status=200;
    }
    else {
      // cerr<<"404 for: "<<req.url.path<<endl;
      resp.status=404;
    }

    std::ostringstream ofs;
    ofs << resp;
    string done;
    done=ofs.str();
    writen2(sock, done.c_str(), done.size());

    close(sock);
    sock = -1;
  }
  catch(const YaHTTP::ParseError& e) {
    vinfolog("Webserver thread died with parse error exception while processing a request from %s: %s", remote.toStringWithPort(), e.what());
    close(sock);
  }
  catch(const std::exception& e) {
    errlog("Webserver thread died with exception while processing a request from %s: %s", remote.toStringWithPort(), e.what());
    close(sock);
  }
  catch(...) {
    errlog("Webserver thread died with exception while processing a request from %s", remote.toStringWithPort());
    close(sock);
  }
}

void setWebserverAPIKey(const boost::optional<std::string> apiKey)
{
  std::lock_guard<std::mutex> lock(g_webserverConfig.lock);

  if (apiKey) {
    g_webserverConfig.apiKey = *apiKey;
  } else {
    g_webserverConfig.apiKey.clear();
  }
}

void setWebserverPassword(const std::string& password)
{
  std::lock_guard<std::mutex> lock(g_webserverConfig.lock);

  g_webserverConfig.password = password;
}

void setWebserverCustomHeaders(const boost::optional<std::map<std::string, std::string> > customHeaders)
{
  std::lock_guard<std::mutex> lock(g_webserverConfig.lock);

  g_webserverConfig.customHeaders = customHeaders;
}

void dnsdistWebserverThread(int sock, const ComboAddress& local)
{
  setThreadName("dnsdist/webserv");
  warnlog("Webserver launched on %s", local.toStringWithPort());
  for(;;) {
    try {
      ComboAddress remote(local);
      int fd = SAccept(sock, remote);
      vinfolog("Got connection from %s", remote.toStringWithPort());
      std::thread t(connectionThread, fd, remote);
      t.detach();
    }
    catch(std::exception& e) {
      errlog("Had an error accepting new webserver connection: %s", e.what());
    }
  }
}
