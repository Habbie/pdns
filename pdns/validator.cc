#include <stdlib.h>
#include <stdio.h>

#include "iputils.hh"

int main(int argc, char** argv)
{
    ComboAddress localaddr;
    int udpfd;

    if(argc > 1)
        localaddr = ComboAddress(argv[1]);
    else
        localaddr = ComboAddress("0.0.0.0:5300");

    cout<<"Listening on "<<localaddr.toStringWithPort()<<endl;

    udpfd = SSocket(localaddr.sin4.sin_family, SOCK_DGRAM, 0);
    if(localaddr.sin4.sin_family == AF_INET6) {
      SSetsockopt(udpfd, IPPROTO_IPV6, IPV6_V6ONLY, 1);
    }

    // bindAny(localaddr.sin4.sin_family, udpfd);

    if(IsAnyAddress(localaddr)) {
      int one=1;
      setsockopt(udpfd, IPPROTO_IP, GEN_IP_PKTINFO, &one, sizeof(one));     // linux supports this, so why not - might fail on other systems
      setsockopt(udpfd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one)); 
    }

    SBind(udpfd, localaddr);    

    listener(udpfd, localaddr);

    exit(0);
}

void listener(int udpfd, ComboAddress localaddr)
{
    ComboAddress remote;
    remote.sin4.sin_family = cs->local.sin4.sin_family;
    char packet[1500];
    struct dnsheader* dh = (struct dnsheader*) packet;
    int len;

    string qname;
    uint16_t qtype;


    for(;;) {
        try {
          len = recvmsg(udpfd, &msgh, 0);
          if(len < (int)sizeof(struct dnsheader)) 
            continue;

        g_stats.queries++;
        if(!acl->match(remote)) {
            g_stats.aclDrops++;
            continue;
        }

      if(dh->qr)    // don't respond to responses
        continue;


    DNSName qname(packet, len, 12, false, &qtype);

    g_rings.queryRing.push_back(qname);

    if(blockFilter) {
        std::lock_guard<std::mutex> lock(g_luamutex);

        if(blockFilter(remote, qname, qtype, dh)) {
          g_stats.blockFilter++;
          continue;
      }
  }


  DNSAction::Action action=DNSAction::Action::None;
  string ruleresult;
  string pool;

  for(const auto& lr : *localRulactions) {
    if(lr.first->matches(remote, qname, qtype, dh, len)) {
      lr.first->d_matches++;
      action=(*lr.second)(remote, qname, qtype, dh, len, &ruleresult);
      if(action != DNSAction::Action::None)
        break;
}
}
switch(action) {
  case DNSAction::Action::Drop:
  g_stats.ruleDrop++;
  continue;
  case DNSAction::Action::Nxdomain:
  dh->rcode = RCode::NXDomain;
  dh->qr=true;
  g_stats.ruleNXDomain++;
  break;
  case DNSAction::Action::Pool: 
  pool=ruleresult;
  break;

  case DNSAction::Action::Spoof:
  ;
  case DNSAction::Action::HeaderModify:
  dh->qr=true;
  break;
  case DNSAction::Action::Allow:
  case DNSAction::Action::None:
  break;
}

      if(dh->qr) { // something turned it into a response
        g_stats.selfAnswered++;
        ComboAddress dest;
        if(HarvestDestinationAddress(&msgh, &dest)) 
          sendfromto(cs->udpFD, packet, len, 0, dest, remote);
      else
          sendto(cs->udpFD, packet, len, 0, (struct sockaddr*)&remote, remote.getSocklen());

      continue;
  }

  DownstreamState* ss = 0;
  auto candidates=getDownstreamCandidates(*localServers, pool);
  auto policy=localPolicy->policy;
  {
    std::lock_guard<std::mutex> lock(g_luamutex);
    ss = policy(candidates, remote, qname, qtype, dh).get();
}

if(!ss)
    continue;

ss->queries++;

unsigned int idOffset = (ss->idOffset++) % ss->idStates.size();
IDState* ids = &ss->idStates[idOffset];

      if(ids->origFD < 0) // if we are reusing, no change in outstanding
        ss->outstanding++;
    else {
        ss->reuseds++;
        g_stats.downstreamTimeouts++;
    }

    ids->origFD = cs->udpFD;
    ids->age = 0;
    ids->origID = dh->id;
    ids->origRemote = remote;
    ids->sentTime.start();
    ids->qname = qname;
    ids->qtype = qtype;
    ids->origDest.sin4.sin_family=0;
    HarvestDestinationAddress(&msgh, &ids->origDest);

    dh->id = idOffset;

    len = send(ss->fd, packet, len, 0);
    if(len < 0) {
        ss->sendErrors++;
        g_stats.downstreamSendErrors++;
    }

    vinfolog("Got query from %s, relayed to %s", remote.toStringWithPort(), ss->remote.toStringWithPort());
}
catch(std::exception& e){
  errlog("Got an error in UDP question thread: %s", e.what());
}
}
return 0;

}