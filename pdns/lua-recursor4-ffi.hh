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

extern "C" {
  typedef struct pdns_ffi_param pdns_ffi_param_t;
  typedef struct pdns_ffi_param_wrapper pdns_ffi_param_wrapper_t;

  typedef struct pdns_ednsoption {
    uint16_t    optionCode;
    uint16_t    len;
    const void* data;
  } pdns_ednsoption_t;

  pdns_ffi_param_t* pdns_ffi_param_unwrap(pdns_ffi_param_wrapper_t* wrap);
  const char* pdns_ffi_param_get_qname(pdns_ffi_param_t* ref) __attribute__ ((visibility ("default")));
  uint16_t pdns_ffi_param_get_qtype(const pdns_ffi_param_t* ref) __attribute__ ((visibility ("default")));
  const char* pdns_ffi_param_get_remote(pdns_ffi_param_t* ref) __attribute__ ((visibility ("default")));
  uint16_t pdns_ffi_param_get_remote_port(const pdns_ffi_param_t* ref) __attribute__ ((visibility ("default")));
  const char* pdns_ffi_param_get_local(pdns_ffi_param_t* ref) __attribute__ ((visibility ("default")));
  uint16_t pdns_ffi_param_get_local_port(const pdns_ffi_param_t* ref) __attribute__ ((visibility ("default")));
  const char* pdns_ffi_param_get_edns_cs(pdns_ffi_param_t* ref) __attribute__ ((visibility ("default")));
  uint8_t pdns_ffi_param_get_edns_cs_source_mask(const pdns_ffi_param_t* ref) __attribute__ ((visibility ("default")));

  // returns the length of the resulting 'out' array. 'out' is not set if the length is 0
  size_t pdns_ffi_param_get_edns_options(pdns_ffi_param_t* ref, const pdns_ednsoption_t** out) __attribute__ ((visibility ("default")));
  size_t pdns_ffi_param_get_edns_options_by_code(pdns_ffi_param_t* ref, uint16_t optionCode, const pdns_ednsoption_t** out) __attribute__ ((visibility ("default")));

  void pdns_ffi_param_set_tag(pdns_ffi_param_t* ref, unsigned int tag) __attribute__ ((visibility ("default")));
  void pdns_ffi_param_add_policytag(pdns_ffi_param_t *ref, const char* name) __attribute__ ((visibility ("default")));
  void pdns_ffi_param_set_requestorid(pdns_ffi_param_t* ref, const char* name) __attribute__ ((visibility ("default")));
  void pdns_ffi_param_set_devicename(pdns_ffi_param_t* ref, const char* name) __attribute__ ((visibility ("default")));
  void pdns_ffi_param_set_deviceid(pdns_ffi_param_t* ref, size_t len, const void* name) __attribute__ ((visibility ("default")));
  void pdns_ffi_param_set_variable(pdns_ffi_param_t* ref, bool variable) __attribute__ ((visibility ("default")));
  void pdns_ffi_param_set_ttl_cap(pdns_ffi_param_t* ref, uint32_t ttl) __attribute__ ((visibility ("default")));


}

struct pdns_ffi_param_wrapper
{
public:
  struct pdns_ffi_param* param;
};

struct pdns_ffi_param
{
public:
  pdns_ffi_param(const DNSName& qname_, uint16_t qtype_, const ComboAddress& local_, const ComboAddress& remote_, const Netmask& ednssubnet_, std::vector<std::string>& policyTags_, const std::map<uint16_t, EDNSOptionView>& ednsOptions_, std::string& requestorId_, std::string& deviceId_, uint32_t& ttlCap_, bool& variable_, bool tcp_): qname(qname_), local(local_), remote(remote_), ednssubnet(ednssubnet_), policyTags(policyTags_), ednsOptions(ednsOptions_), requestorId(requestorId_), deviceId(deviceId_), ttlCap(ttlCap_), variable(variable_), qtype(qtype_), tcp(tcp_)
  {
  }

  std::unique_ptr<std::string> qnameStr{nullptr};
  std::unique_ptr<std::string> localStr{nullptr};
  std::unique_ptr<std::string> remoteStr{nullptr};
  std::unique_ptr<std::string> ednssubnetStr{nullptr};
  std::vector<pdns_ednsoption_t> ednsOptionsVect;

  const DNSName& qname;
  const ComboAddress& local;
  const ComboAddress& remote;
  const Netmask& ednssubnet;
  std::vector<std::string>& policyTags;
  const std::map<uint16_t, EDNSOptionView>& ednsOptions;
  std::string& requestorId;
  std::string& deviceId;
  uint32_t& ttlCap;
  bool& variable;

  unsigned int tag{0};
  uint16_t qtype;
  bool tcp;
};

