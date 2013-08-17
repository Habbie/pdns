#include "dnsparser.hh"
#include "sstuff.hh"
#include "misc.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"
#include "statbag.hh"
#include "base32.hh"
#include "dnssecinfra.hh"
#include <boost/foreach.hpp>

StatBag S;

typedef std::pair<string,string> nsec3;
typedef set<nsec3> nsec3set;

string nsec3Hash(const string &qname, const string &salt, unsigned int iters)
{
  return toBase32Hex(hashQNameWithSalt(iters, salt, qname));
}

void proveOrDeny(const nsec3set &nsec3s, const string &qname, const string &salt, unsigned int iters, set<string> &proven, set<string> &denied)
{
  string hashed = nsec3Hash(qname, salt, iters);

  // cerr<<"proveOrDeny(.., '"<<qname<<"', ..)"<<endl;
  // cerr<<"hashed: "<<hashed<<endl;
  for(nsec3set::const_iterator pos=nsec3s.begin(); pos != nsec3s.end(); ++pos) {
    string base=(*pos).first;
    string next=(*pos).second;

    if(hashed == base)
    {
      proven.insert(qname);
      cout<<qname<<" ("<<hashed<<") proven by base of "<<base<<".."<<next<<endl;
    }
    if(hashed == next)
    {
      proven.insert(qname);
      cout<<qname<<" ("<<hashed<<") proven by next of "<<base<<".."<<next<<endl;
    }
    if((hashed > base && hashed < next) ||
       (next < base && (hashed < next || hashed > base)))
    {
      denied.insert(qname);
      cout<<qname<<" ("<<hashed<<") denied by "<<base<<".."<<next<<endl;
    }
    if (base == next && base != hashed)
    {
      denied.insert(qname);
      cout<<qname<<" ("<<hashed<<") denied by "<<base<<".."<<next<<endl;
    }
  }
}

class TCPResolver : public boost::noncopyable
{
public:
  TCPResolver(ComboAddress addr)
  {
    d_rsock=new Socket(InterNetwork, Stream);
    d_rsock->connect(addr);
  }

  ~TCPResolver()
  {
    delete d_rsock;
  }

  string query(string qname, uint16_t qtype)
  {
    vector<uint8_t> packet;
    DNSPacketWriter pw(packet, qname, qtype);

    // recurse
    pw.getHeader()->rd=true;

    // we'll do the validation
    pw.getHeader()->cd=true;
    pw.getHeader()->ad=true;

    // we do require DNSSEC records to do that!
    pw.addOpt(2800, 0, EDNSOpts::DNSSECOK);
    pw.commit();

    uint16_t len;
    len = htons(packet.size());
    if(d_rsock->write((char *) &len, 2) != 2)
      throw PDNSException("tcp write failed");

    d_rsock->writen(string((char*)&*packet.begin(), (char*)&*packet.end()));
    
    if(d_rsock->read((char *) &len, 2) != 2)
      throw PDNSException("tcp read failed");

    len=ntohs(len);
    char *creply = new char[len];
    int n=0;
    int numread;
    while(n<len) {
      numread=d_rsock->read(creply+n, len-n);
      if(numread<0)
        throw PDNSException("tcp read failed");
      n+=numread;
    }

    string reply(creply, len);
    delete[] creply;

    return reply;
  }

  Socket *d_rsock;
};

int main(int argc, char** argv)
try
{
  reportAllTypes();

  if(argc < 5) {
    cerr<<"Syntax: oneshot IP-address port question question-type\n";
    exit(EXIT_FAILURE);
  }

  string qname=argv[3];
  uint16_t qtype=DNSRecordContent::TypeToNumber(argv[4]);

  ComboAddress dest(argv[1] + (*argv[1]=='@'), atoi(argv[2]));
  TCPResolver tr(dest);

  // fetch requested result
  MOADNSParser mdpA(tr.query(qname, qtype));

  vector<shared_ptr<DNSRecordContent> > ARecords;
  RRSIGRecordContent rrc;
  for(MOADNSParser::answers_t::const_iterator i=mdpA.d_answers.begin(); i!=mdpA.d_answers.end(); ++i) {     
    if(i->first.d_type == QType::A && i->first.d_place == DNSRecord::Answer) {
      ARecords.push_back(i->first.d_content);

      // NSEC3RecordContent r = dynamic_cast<NSEC3RecordContent&> (*(i->first.d_content));
      // // nsec3.insert(new nsec3()
      // // cerr<<toBase32Hex(r.d_nexthash)<<endl;
      // vector<string> parts;
      // boost::split(parts, i->first.d_label, boost::is_any_of("."));
      // nsec3s.insert(make_pair(toLower(parts[0]), toBase32Hex(r.d_nexthash)));
      // nsec3salt = r.d_salt;
      // nsec3iters = r.d_iterations;
    }
    else if(i->first.d_type == QType::RRSIG && i->first.d_place == DNSRecord::Answer) {
      rrc = dynamic_cast<RRSIGRecordContent&> (*(i->first.d_content));
      cerr<<"got rrsig in "<<i->first.d_place<<endl;
    }
  }
  cerr<<"got "<<ARecords.size()<<" A records"<<endl;
  cerr<<"signer is "<<rrc.d_signer<<endl;
  // fetch DNSKEY
  MOADNSParser mdpDNSKEY(tr.query(rrc.d_signer, QType::DNSKEY));

  vector<shared_ptr<DNSRecordContent> > DNSKEYRecords;
  for(MOADNSParser::answers_t::const_iterator i=mdpDNSKEY.d_answers.begin(); i!=mdpDNSKEY.d_answers.end(); ++i) {     
    if(i->first.d_type == QType::DNSKEY && i->first.d_place == DNSRecord::Answer) {
      DNSKEYRecords.push_back(i->first.d_content);
    }
  }
  cerr<<"got "<<DNSKEYRecords.size()<<" DNSKEY records"<<endl;

  string msg=getMessageForRRSET(qname, rrc, ARecords);
  BOOST_FOREACH(shared_ptr<DNSRecordContent> r, DNSKEYRecords) {
    DNSKEYRecordContent drc = dynamic_cast<DNSKEYRecordContent&>(*(r));
    if(rrc.d_tag==drc.getTag())
      cerr<<"Verify with DNSKEY "<<drc.getTag()<<": "<<DNSCryptoKeyEngine::makeFromPublicKeyString(drc.d_algorithm, drc.d_key)->verify(msg, rrc.d_signature)<<endl;
  }

  exit(EXIT_SUCCESS);
}
catch(std::exception &e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
