#include "dnspcap.hh"
#include "dnswriter.hh"
#include <fstream>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <vector>

string strip(string& in)
{
    string &out = in;

    if(out[0] == ' ') out = out.substr(1, in.size()-1);
    if(out[0] == '\'' and out[out.size()-1] == '\'')
        out = out.substr(1, out.size()-2);

    return out;
}

void setaddress(struct in_addr *out, u_short *port, const string &value)
{
  string myval = value;
  u_short myport;
  std::replace( myval.begin(), myval.end(), '#', ':');
  // cout<<"   setaddress got ["<<myval<<"]"<<endl;
  ComboAddress ca(myval);
  memcpy(out, &ca.sin4.sin_addr.s_addr, sizeof(ca.sin4.sin_addr.s_addr));
  myport = ca.sin4.sin_port;
  memcpy(port, &myport, sizeof(myport));
}

void setflags(dnsheader *dh, string &flags)
{
  vector<string> flagv;

  if(flags[0] != '(' || flags[flags.size()-1] != ')')
    throw runtime_error("invalid flags");
  flags = flags.substr(1, flags.size()-2);
  // cout<<"  got flags: ["<<flags<<"]"<<endl;
  boost::split(flagv, flags, boost::is_any_of(" "));
  for(auto &flag: flagv) {
    // cout<<"   got flag: "<<flag<<endl;
    flag = strip(flag);
    if (flag == "RD") {
      // cout<<"    setting RD"<<endl;
      dh->rd=1;
    } else if(flag == "RA") {
      // cout<<"    setting RA"<<endl;
      dh->ra=1;
    }
  }
}

int main(int argc, char **argv)
{
  pdns_pcap_file_header pfh;
  std::ifstream infile(argv[1]);
  FILE *out=fopen(argv[2], "w");

  pfh.magic = htonl(0xa1b2c3d4);
  pfh.version_major = htons(2);
  pfh.version_minor = htons(4);
  pfh.thiszone = 0;
  pfh.sigfigs = 0;
  pfh.snaplen = htonl(1500);
  pfh.linktype = htonl(101);

  fwrite(&pfh, 1, sizeof(pfh), out);

  string token;

  struct pdns_pcap_pkthdr pheader;
  struct udphdr uh;
  struct ip ih;
  DNSName qname;
  QType qtype;
  uint16_t qid;
  string flags;
  uint16_t reqsize;

  uint16_t ipid = 0;

  for(std::string line ; std::getline(infile, line) ; ) {
    ih.ip_v=4;
    ih.ip_hl = sizeof(ih) >> 2;
    ih.ip_tos = 0;
    // ih.ip_len
    ih.ip_id=ipid++;
    ih.ip_off=0;
    ih.ip_ttl=127;
    ih.ip_p=17;
    ih.ip_sum=0;

    vector<string> parts;

    // cout<<"got line '"<<line<<"'"<<endl;
    boost:split(parts, line, boost::is_any_of(" "));
    // cout<<"line has "<<parts.size()<<" parts"<<endl;

    vector<string> tokens;
    bool combine = false;
    for(const auto& i : parts) {
      // cout<<"part: "<<i<<endl;

      if (!i.size()) {
        tokens.push_back(i);
        continue;
      } else if (combine) {
        tokens[tokens.size()-1] += " " + i;
      } else if (!combine && (i.at(0) == '(' ||
                              i.substr(0, 4) == "LVP(")) {
        tokens.push_back(i);
        combine = true;
      } else {
        tokens.push_back(i);
      }

      if (i.at(i.size()-1) == ')')
        combine = false;

    }
    for(const auto& i : tokens) {
      // cout<<"token: "<<i<<endl;
    }

    // cout<<"line has "<<tokens.size()<<" tokens"<<endl;

    uint32_t ts;
    ts = std::stoul(tokens[0]);
    // cout<<"   got timestamp "<<ts<<endl;
    pheader.ts.tv_sec = htonl(ts);
    pheader.ts.tv_usec = 0;

    setaddress(&ih.ip_src, &uh.uh_sport, tokens[2]);
    setaddress(&ih.ip_dst, &uh.uh_dport, tokens[3]);

    qname = DNSName(tokens[4]);
    // cout<<"   got qname "<<tokens[4]<<" parsed as "<<qname.toString()<<endl;

    if (tokens[5] != "IN") {
      cerr<<"unknown query-class"<<endl;
      continue;
    }

    qtype = tokens[6];

    qid = std::stoul(tokens[9]);

    flags = tokens[10];

    // cout<<" writing packet with qname "<<qname.toString()<<endl;
    vector<uint8_t> content;
    DNSPacketWriter pw(content, qname, qtype.getCode(), 1, 0);
    pw.getHeader()->id = htons(qid);
    setflags(pw.getHeader(), flags);
    pw.commit();
    uh.uh_ulen = htons(sizeof(uh) + content.size());
    uh.uh_sum = 0;

    ih.ip_len = htons(sizeof(ih) + sizeof(uh) + content.size());

    pheader.len = htonl(sizeof(ih) + sizeof(uh) + content.size());
    pheader.caplen = pheader.len;

    // cout<<"lengths pcap/ip/udp/dns/reqsize: "<<ntohl(pheader.len)<<", "
    //                                          <<ntohs(ih.ip_len)<<", "
    //                                          <<ntohs(uh.uh_ulen)<<", "
    //                                          <<content.size()<<", "
    //                                          <<reqsize<<endl;

    // if (content.size() != reqsize) throw runtime_error("content/reqsize mismatch");

    fwrite(&pheader, 1, sizeof(pheader), out);
    fwrite(&ih, 1, sizeof(ih), out);
    fwrite(&uh, 1, sizeof(uh), out);
    fwrite(content.data(), 1, content.size(), out);
  }
}
