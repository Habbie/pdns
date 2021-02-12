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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "dnsrecords.hh"

string NSECBitmap::getZoneRepresentation() const
{
  string ret;

  if (d_bitset) {
    size_t found = 0;
    size_t l_count = d_bitset->count();
    for(size_t idx = 0; idx < nbTypes && found < l_count; ++idx) {
      if (!d_bitset->test(idx)) {
        continue;
      }
      found++;

      ret+=" ";
      ret+=DNSRecordContent::NumberToType(idx);
    }
  }
  else {
    for(const auto& type : d_set) {
      ret+=" ";
      ret+=DNSRecordContent::NumberToType(type);
    }
  }

  return ret;
}

void NSECRecordContent::report()
{
  regist(1, 47, &make, &make, "NSEC");
}

std::shared_ptr<DNSRecordContent> NSECRecordContent::make(const string& content)
{
  return std::make_shared<NSECRecordContent>(content);
}

NSECRecordContent::NSECRecordContent(const string& content, const DNSName& zone)
{
  RecordTextReader rtr(content, zone);
  rtr.xfrName(d_next);

  while(!rtr.eof()) {
    uint16_t type;
    rtr.xfrType(type);
    set(type);
  }
}

void NSECRecordContent::toPacket(DNSPacketWriter& pw)
{
  pw.xfrName(d_next);
  pw.xfrNSECBitmap(d_bitmap);
}

std::shared_ptr<NSECRecordContent::DNSRecordContent> NSECRecordContent::make(const DNSRecord &dr, PacketReader& pr)
{
  auto ret=std::make_shared<NSECRecordContent>();
  pr.xfrName(ret->d_next);
  pr.xfrNSECBitmap(ret->d_bitmap);

  return ret;
}

string NSECRecordContent::getZoneRepresentation(bool noDot) const
{
  string ret;
  RecordTextWriter rtw(ret);
  rtw.xfrName(d_next);
  rtw.xfrNSECBitmap(d_bitmap);
  return ret;
}

////// begin of NSEC3

void NSEC3RecordContent::report()
{
  regist(1, 50, &make, &make, "NSEC3");
}

std::shared_ptr<DNSRecordContent> NSEC3RecordContent::make(const string& content)
{
  return std::make_shared<NSEC3RecordContent>(content);
}

NSEC3RecordContent::NSEC3RecordContent(const string& content, const DNSName& zone)
{
  RecordTextReader rtr(content, zone);
  rtr.xfr8BitInt(d_algorithm);
  rtr.xfr8BitInt(d_flags);
  rtr.xfr16BitInt(d_iterations);

  rtr.xfrHexBlob(d_salt);
  rtr.xfrBase32HexBlob(d_nexthash);
  
  rtr.xfrNSECBitmap(d_bitmap);
}

void NSEC3RecordContent::toPacket(DNSPacketWriter& pw) 
{
  pw.xfr8BitInt(d_algorithm);
  pw.xfr8BitInt(d_flags);
  pw.xfr16BitInt(d_iterations);
  pw.xfr8BitInt(d_salt.length());
  pw.xfrBlob(d_salt);

  pw.xfr8BitInt(d_nexthash.length());
  pw.xfrBlob(d_nexthash);

  pw.xfrNSECBitmap(d_bitmap);
}

std::shared_ptr<NSEC3RecordContent::DNSRecordContent> NSEC3RecordContent::make(const DNSRecord &dr, PacketReader& pr)
{
  auto ret=std::make_shared<NSEC3RecordContent>();
  pr.xfr8BitInt(ret->d_algorithm);
  pr.xfr8BitInt(ret->d_flags);
  pr.xfr16BitInt(ret->d_iterations);
  uint8_t len;
  pr.xfr8BitInt(len);
  pr.xfrBlob(ret->d_salt, len);

  pr.xfr8BitInt(len);
  pr.xfrBlob(ret->d_nexthash, len);
  pr.xfrNSECBitmap(ret->d_bitmap);
  return ret;
}

string NSEC3RecordContent::getZoneRepresentation(bool noDot) const
{
  string ret;
  RecordTextWriter rtw(ret);
  rtw.xfr8BitInt(d_algorithm);
  rtw.xfr8BitInt(d_flags);
  rtw.xfr16BitInt(d_iterations);

  rtw.xfrHexBlob(d_salt);
  rtw.xfrBase32HexBlob(d_nexthash);

  return ret + d_bitmap.getZoneRepresentation();
}


void NSEC3PARAMRecordContent::report()
{
  regist(1, 51, &make, &make, "NSEC3PARAM");
  regist(254, 51, &make, &make, "NSEC3PARAM");
}

std::shared_ptr<DNSRecordContent> NSEC3PARAMRecordContent::make(const string& content)
{
  return std::make_shared<NSEC3PARAMRecordContent>(content);
}

NSEC3PARAMRecordContent::NSEC3PARAMRecordContent(const string& content, const DNSName& zone)
{
  RecordTextReader rtr(content, zone);
  rtr.xfr8BitInt(d_algorithm); 
  rtr.xfr8BitInt(d_flags); 
  rtr.xfr16BitInt(d_iterations); 
  rtr.xfrHexBlob(d_salt);
}

void NSEC3PARAMRecordContent::toPacket(DNSPacketWriter& pw) 
{
  pw.xfr8BitInt(d_algorithm); 
        pw.xfr8BitInt(d_flags); 
        pw.xfr16BitInt(d_iterations); 
  pw.xfr8BitInt(d_salt.length());
  // cerr<<"salt: '"<<makeHexDump(d_salt)<<"', "<<d_salt.length()<<endl;
  pw.xfrBlob(d_salt);
}

std::shared_ptr<NSEC3PARAMRecordContent::DNSRecordContent> NSEC3PARAMRecordContent::make(const DNSRecord &dr, PacketReader& pr)
{
  auto ret=std::make_shared<NSEC3PARAMRecordContent>();
  pr.xfr8BitInt(ret->d_algorithm); 
        pr.xfr8BitInt(ret->d_flags); 
        pr.xfr16BitInt(ret->d_iterations); 
  uint8_t len;
  pr.xfr8BitInt(len);
  pr.xfrHexBlob(ret->d_salt, len);
  return ret;
}

string NSEC3PARAMRecordContent::getZoneRepresentation(bool noDot) const
{
  string ret;
  RecordTextWriter rtw(ret);
  rtw.xfr8BitInt(d_algorithm); 
        rtw.xfr8BitInt(d_flags); 
        rtw.xfr16BitInt(d_iterations); 
  rtw.xfrHexBlob(d_salt);
  return ret;
}

////// end of NSEC3
