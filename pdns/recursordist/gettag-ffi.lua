local ffi = require("ffi")

ffi.cdef[[
  typedef struct pdns_ffi_param pdns_ffi_param_t;
  typedef struct pdns_ffi_param_wrapper pdns_ffi_param_wrapper_t;

  typedef struct pdns_ednsoption {
    uint16_t    optionCode;
    uint16_t    len;
    const void* data;
  } pdns_ednsoption_t;

  pdns_ffi_param_t* pdns_ffi_param_unwrap(pdns_ffi_param_wrapper_t* wrap);

  const char* pdns_ffi_param_get_qname(pdns_ffi_param_t* ref);
  uint16_t pdns_ffi_param_get_qtype(const pdns_ffi_param_t* ref);
  const char* pdns_ffi_param_get_remote(pdns_ffi_param_t* ref);
  uint16_t pdns_ffi_param_get_remote_port(const pdns_ffi_param_t* ref);
  const char* pdns_ffi_param_get_local(pdns_ffi_param_t* ref);
  uint16_t pdns_ffi_param_get_local_port(const pdns_ffi_param_t* ref);
  const char* pdns_ffi_param_get_edns_cs(pdns_ffi_param_t* ref);
  uint8_t pdns_ffi_param_get_edns_cs_source_mask(const pdns_ffi_param_t* ref);

  // returns the length of the resulting 'out' array. 'out' is not set if the length is 0                                                                                                                          
  size_t pdns_ffi_param_get_edns_options(pdns_ffi_param_t* ref, const pdns_ednsoption_t** out);
  size_t pdns_ffi_param_get_edns_options_by_code(pdns_ffi_param_t* ref, uint16_t optionCode, const pdns_ednsoption_t** out);

  void pdns_ffi_param_set_tag(pdns_ffi_param_t* ref, unsigned int tag);
  void pdns_ffi_param_add_policytag(pdns_ffi_param_t *ref, const char* name);
  void pdns_ffi_param_set_requestorid(pdns_ffi_param_t* ref, const char* name);
  void pdns_ffi_param_set_devicename(pdns_ffi_param_t* ref, const char* name);
  void pdns_ffi_param_set_deviceid(pdns_ffi_param_t* ref, size_t len, const void* name);
  void pdns_ffi_param_set_variable(pdns_ffi_param_t* ref, bool variable);
  void pdns_ffi_param_set_ttl_cap(pdns_ffi_param_t* ref, uint32_t ttl);
]]

function gettag_ffi(_obj)
obj = ffi.C.pdns_ffi_param_unwrap(_obj)

ffi.C.pdns_ffi_param_set_ttl_cap(obj, 5)
ffi.C.pdns_ffi_param_set_variable(obj, true)
print("gettag_ffi obj argument", obj)
local pFoo = ffi.new 'const pdns_ednsoption_t *[1]'
  local count = ffi.C.pdns_ffi_param_get_edns_options(obj, pFoo)
  print("pdns_ffi_param_get_edns_options count", count)
  if count > 0 then
    for i=0,tonumber(count)-1 do
      print(" i", i)
      print("  optionCode", pFoo[0][i].optionCode)
      print("  data", pFoo[0][i].data)
      print("  len", pFoo[0][i].len)
    end
  end
  pFoo = ffi.new 'const pdns_ednsoption_t *[1]'
  count = ffi.C.pdns_ffi_param_get_edns_options_by_code(obj, 8, pFoo)
  print("pdns_ffi_param_get_edns_options_by_code count", count)
  if count > 0 then
    for i=0,tonumber(count)-1 do
      print(" i", i)
      print("  optionCode", pFoo[0][i].optionCode)
      print("  len", pFoo[0][i].len)
    end
  end
  print("pdns_ffi_param_get_edns_cs", ffi.C.pdns_ffi_param_get_edns_cs(obj))
return {}
end

