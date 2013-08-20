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
    cerr<<"Q "<<qname<<"/"<<DNSRecordContent::NumberToType(qtype)<<endl;
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

typedef pair<string, uint16_t> NT;
typedef std::multimap<NT, shared_ptr<DNSRecordContent> > recmap_t;
typedef std::multimap<NT, RRSIGRecordContent> sigmap_t;
typedef std::multimap<NT, shared_ptr<DNSRecordContent> > nsecmap_t;

bool compareDS(DSRecordContent a, DSRecordContent b)
{
  return a.d_tag == b.d_tag &&
         a.d_algorithm == b.d_algorithm &&
         a.d_digesttype == b.d_digesttype &&
         a.d_digest == b.d_digest;
}

recmap_t getAndVerify(TCPResolver &tr, string qname, uint16_t qtype, int depth=0, bool needDS=false)
{
  recmap_t recs; // all records that we fetched
  recmap_t vrecs; // verified subset of recs
  sigmap_t sigs;
  nsecmap_t nsecs;

  cerr<<"at depth "<<depth<<" fetching "<<qname<<"/"<<DNSRecordContent::NumberToType(qtype)<<" ("<<(needDS ? "KSK" : "ZSK")<<")"<<endl;
  if(qname=="" and qtype==QType::DS) {
    vrecs.insert(make_pair(NT("", QType::DS), DNSRecordContent::mastermake(QType::DS, 1, "19036 8 2 49aac11d7b6f6446702e54a1607371607a1a41855200fd2ce1cdde32f24e8fb5")));
    cerr<<"DS/. - returning root anchor"<<endl;
    return vrecs;
  }

  MOADNSParser mdp(tr.query(qname, qtype));

  for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i!=mdp.d_answers.end(); ++i) {
    cerr<<"ZR ("<<i->first.d_place<<") "<<i->first.d_label<<" "<<DNSRecordContent::NumberToType(i->first.d_type)<<" "<<i->first.d_content->getZoneRepresentation()<<endl;    
    if(i->first.d_type == QType::RRSIG) {
      RRSIGRecordContent rrc=dynamic_cast<RRSIGRecordContent&> (*(i->first.d_content));
      sigs.insert(make_pair(NT(stripDot(i->first.d_label), rrc.d_type), rrc));
    }
    else if(i->first.d_place == DNSRecord::Answer) {
      recs.insert(make_pair(NT(stripDot(i->first.d_label), i->first.d_type), i->first.d_content));
    }
  }
  cerr<<"got "<<recs.size()<<" recs, "<<sigs.size()<<" sigs"<<endl;
  cerr<<"question was "<<qname<<"/"<<DNSRecordContent::NumberToType(qtype)<<", got "<<recs.count(NT(qname,qtype))<<" recs"<<endl;
  pair<recmap_t::const_iterator,recmap_t::const_iterator> b = make_pair(recs.begin(), recs.end()); // recs.equal_range(NT(qname, qtype));
  for(recmap_t::const_iterator i=b.first; i!= b.second; ++i) cerr<<(i->first.first)<<"/"<<(i->first.second)<<": "<<i->second->getZoneRepresentation()<<endl;
  cerr<<"END"<<endl;
  cerr<<"got "<<sigs.count(NT(qname,qtype))<<" related sigs"<<endl;
  // typedef std::multimap<NT, RRSIGRecordContent >::const_iterator J;
  // pair<J,J> c = sigs.equal_range(NT(qname, qtype));
  // for(J i=c.first; i!= c.second; ++i) cerr<<(i->first.first)<<"/"<<(i->first.second)<<": "<<i->second.getZoneRepresentation()<<endl;

  cerr<<"fetching keys for validation"<<endl;
  pair<sigmap_t::const_iterator,sigmap_t::const_iterator> r = sigs.equal_range(NT(qname, qtype));
  cerr<<"got "<<sigs.size()<<" sigs, "<<sigs.count(NT(qname, qtype))<<" match"<<endl;
  for(sigmap_t::const_iterator i=r.first; i!=r.second; ++i)
  {
    RRSIGRecordContent rrc=i->second;
    cerr<<"got RRSIG "<<(i->first.first)<<"/"<<(i->first.second)<<": "<<rrc.getZoneRepresentation()<<endl;
    if(qname == stripDot(rrc.d_signer) && needDS)
    {
      cerr<<"finding upstream DS for "<<rrc.d_signer<<endl;
      recmap_t ds=getAndVerify(tr, stripDot(rrc.d_signer), QType::DS, depth+1);
      if(!ds.size())
      {
        cerr<<"no DS for "<<rrc.d_signer<<", giving up"<<endl;
        cerr<<"returning empty (no DS) depth "<<depth<<endl;

        // return vrecs;
      }
      else
      {
        pair<recmap_t::const_iterator,recmap_t::const_iterator> r = recs.equal_range(NT(qname, qtype));
        cerr<<"got "<<recs.count(NT(qname, qtype))<<" DNSKEYs to check against DS"<<endl;
        for(recmap_t::const_iterator i=r.first; i!=r.second; ++i)
        {
          DNSKEYRecordContent drc=dynamic_cast<DNSKEYRecordContent&> (*(i->second));
          pair<recmap_t::const_iterator,recmap_t::const_iterator> r = ds.equal_range(NT(qname, QType::DS));
          cerr<<"got "<<ds.count(NT(qname, QType::DS))<<" DSs to check against DNSKEY"<<endl;
          for(recmap_t::const_iterator j=r.first; j!=r.second; ++j)
          {
            DSRecordContent dsrc=dynamic_cast<DSRecordContent&> (*(j->second));
            cerr<<"need to check DNSKEY "<<drc.getTag()<<"/"<<" against DS "<<dsrc.d_tag<<endl;
            cerr<<"DS from DNSKEY "<<makeDSFromDNSKey(qname, drc, dsrc.d_digesttype).getZoneRepresentation()<<endl;
            cerr<<"DS content "<<dsrc.getZoneRepresentation()<<endl;
            DSRecordContent dsrc2=makeDSFromDNSKey(qname, drc, dsrc.d_digesttype);
            if(dsrc.d_tag == dsrc2.d_tag)
            {
              if(compareDS(dsrc, dsrc2))
              {
                cerr<<"DNSKEY verified against DS "<<dsrc.getZoneRepresentation()<<endl;
                vrecs.insert(make_pair(NT(qname, qtype), i->second));
              }
              else
              {
                cerr<<"FAILED to match"<<endl;
              }
            }
          }
        }
        cerr<<"returning "<<vrecs.size()<<" DS-verified DNSKEYs for "<<qname<<endl;
        r = make_pair(vrecs.begin(), vrecs.end());
        for(recmap_t::const_iterator i=r.first; i!=r.second; i++)
        {
          cout<<i->first.first<<" "<<i->first.second<<" "<<i->second->getZoneRepresentation()<<endl;
        }
        cerr<<"END"<<endl;
        // return vrecs;
        // cerr<<"returning empty (no DS/DNSKEY match) at depth "<<depth<<endl;
        // recs.clear();
        // return recs;
      }
    }
    else
    {
      cerr<<"finding DNSKEYs for "<<rrc.d_signer<<endl;
      recmap_t keys=getAndVerify(tr, stripDot(rrc.d_signer), QType::DNSKEY, depth+1, qtype == QType::DNSKEY);
      if(!keys.size())
      {
        cerr<<"returning empty (no DNSKEY for ["<<stripDot(rrc.d_signer)<<"]) at depth "<<depth<<endl;
        // return vrecs;
      }

      vector<shared_ptr<DNSRecordContent> > toSign;
      pair<recmap_t::const_iterator,recmap_t::const_iterator> r = recs.equal_range(NT(qname, qtype));
      for(recmap_t::const_iterator i=r.first; i!=r.second; i++)
      {
        toSign.push_back(i->second);
      }

      string msg=getMessageForRRSET(qname, rrc, toSign);

      r = keys.equal_range(NT(stripDot(rrc.d_signer), QType::DNSKEY));

      for(recmap_t::const_iterator i=r.first; i!=r.second; i++)
      {
        DNSKEYRecordContent drc=dynamic_cast<DNSKEYRecordContent&> (*(i->second));
        if(rrc.d_tag == drc.getTag())
        {
          if(DNSCryptoKeyEngine::makeFromPublicKeyString(drc.d_algorithm, drc.d_key)->verify(msg, rrc.d_signature))
          {
            cerr<<"RRSIG "<<rrc.getZoneRepresentation()<<" verified with DNSKEY "<<drc.getZoneRepresentation()<<endl;
            for(vector<shared_ptr<DNSRecordContent> >::const_iterator i=toSign.begin(); i!=toSign.end(); i++)
            {
              vrecs.insert(make_pair(NT(qname, qtype), *i));
            }
            // return vrecs;
          }
          else
          {
            cerr<<"FAILED with DNSKEY "<<drc.getTag()<<endl;
          }
        }
      }
    }
  }
  // cerr<<"signer is "<<rrc.d_signer<<endl;
  // fetch DNSKEY
  // MOADNSParser mdpDNSKEY(tr.query(rrc.d_signer, QType::DNSKEY));
  cerr<<"returning "<<vrecs.size()<<" records at depth "<<depth<<endl;
  return vrecs;
}


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

  recmap_t recs=getAndVerify(tr, qname, qtype, 0);
  cout<<"got "<<recs.size()<<" verified records"<<endl;

  pair<recmap_t::const_iterator,recmap_t::const_iterator> r = make_pair(recs.begin(), recs.end());
  for(recmap_t::const_iterator i=r.first; i!=r.second; i++)
  {
    cout<<i->first.first<<" "<<DNSRecordContent::NumberToType(i->first.second)<<" "<<i->second->getZoneRepresentation()<<endl;
  }
  // // fetch requested result
  // MOADNSParser mdpA(tr.query(qname, qtype));

  // vector<shared_ptr<DNSRecordContent> > ARecords;
  // RRSIGRecordContent rrc;


  // vector<shared_ptr<DNSRecordContent> > DNSKEYRecords;
  // for(MOADNSParser::answers_t::const_iterator i=mdpDNSKEY.d_answers.begin(); i!=mdpDNSKEY.d_answers.end(); ++i) {
  //   if(i->first.d_type == QType::DNSKEY && i->first.d_place == DNSRecord::Answer) {
  //     DNSKEYRecords.push_back(i->first.d_content);
  //   }
  // }
  // cerr<<"got "<<DNSKEYRecords.size()<<" DNSKEY records"<<endl;

  // string msg=getMessageForRRSET(qname, rrc, ARecords);
  // BOOST_FOREACH(shared_ptr<DNSRecordContent> r, DNSKEYRecords) {
  //   DNSKEYRecordContent drc = dynamic_cast<DNSKEYRecordContent&>(*(r));
  //   if(rrc.d_tag==drc.getTag())
  //     cerr<<"Verify with DNSKEY "<<drc.getTag()<<": "<<DNSCryptoKeyEngine::makeFromPublicKeyString(drc.d_algorithm, drc.d_key)->verify(msg, rrc.d_signature)<<endl;
  // }

  exit(EXIT_SUCCESS);
}
catch(std::exception &e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
