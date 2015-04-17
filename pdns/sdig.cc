#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "dnsparser.hh"
#include "sstuff.hh"
#include "misc.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"
#include "statbag.hh"
#include <boost/array.hpp>
#include <sstream>
#include <istream>
StatBag S;

int main(int argc, char** argv)
try
{
  bool hidesoadetails=false;
  bool showflags=false;

  reportAllTypes();

  std::stringstream replystr;
  replystr << std::cin.rdbuf();

  MOADNSParser mdp(replystr.str());
  cout<<"Reply to question for qname='"<<mdp.d_qname<<"', qtype="<<DNSRecordContent::NumberToType(mdp.d_qtype)<<endl;
  cout<<"Rcode: "<<mdp.d_header.rcode<<", RD: "<<mdp.d_header.rd<<", QR: "<<mdp.d_header.qr;
  cout<<", TC: "<<mdp.d_header.tc<<", AA: "<<mdp.d_header.aa<<", opcode: "<<mdp.d_header.opcode<<endl;

  for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i!=mdp.d_answers.end(); ++i) {          
    cout<<i->first.d_place-1<<"\t"<<i->first.d_label<<"\t"<<i->first.d_class<<"\t"<<DNSRecordContent::NumberToType(i->first.d_type);
    if(i->first.d_type == QType::RRSIG && i->first.d_class==1)
    {
      string zoneRep = i->first.d_content->getZoneRepresentation();
      vector<string> parts;
      stringtok(parts, zoneRep);
      cout<<"\t"<<i->first.d_ttl<<"\t"<< parts[0]<<" "<<parts[1]<<" "<<parts[2]<<" "<<parts[3]<<" [expiry] [inception] [keytag] "<<parts[7]<<" ...\n";
    }
    else if(!showflags && i->first.d_type == QType::NSEC3 && i->first.d_class==1)
    {
      string zoneRep = i->first.d_content->getZoneRepresentation();
      vector<string> parts;
      stringtok(parts, zoneRep);
      cout<<"\t"<<i->first.d_ttl<<"\t"<< parts[0]<<" [flags] "<<parts[2]<<" "<<parts[3]<<" "<<parts[4];
      for(vector<string>::iterator iter = parts.begin()+5; iter != parts.end(); ++iter)
        cout<<" "<<*iter;
      cout<<"\n";
    }
    else if(i->first.d_type == QType::DNSKEY  && i->first.d_class==1)
    {
      string zoneRep = i->first.d_content->getZoneRepresentation();
      vector<string> parts;
      stringtok(parts, zoneRep);
      cout<<"\t"<<i->first.d_ttl<<"\t"<< parts[0]<<" "<<parts[1]<<" "<<parts[2]<<" ...\n";
    }
    else if (i->first.d_type == QType::SOA && hidesoadetails  && i->first.d_class==1)
    {
      string zoneRep = i->first.d_content->getZoneRepresentation();
      vector<string> parts;
      stringtok(parts, zoneRep);
      cout<<"\t"<<i->first.d_ttl<<"\t"<<parts[0]<<" "<<parts[1]<<" [serial] "<<parts[3]<<" "<<parts[4]<<" "<<parts[5]<<" "<<parts[6]<<"\n";
    }
    else
    {
      cout<<"\t"<<i->first.d_ttl<<"\t"<< i->first.d_content->getZoneRepresentation()<<"\n";
    }

  }

  EDNSOpts edo;
  if(getEDNSOpts(mdp, &edo)) {
//    cerr<<"Have "<<edo.d_options.size()<<" options!"<<endl;
    for(vector<pair<uint16_t, string> >::const_iterator iter = edo.d_options.begin();
        iter != edo.d_options.end(); 
        ++iter) {
      if(iter->first == 5) {// 'EDNS PING'
        cerr<<"Have ednsping: '"<<iter->second<<"'\n";
        //if(iter->second == ping) 
         // cerr<<"It is correct!"<<endl;
      }
      else {
        cerr<<"Have unknown option "<<(int)iter->first<<endl;
      }
    }

  }

}
catch(std::exception &e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
