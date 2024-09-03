#include "lmdb-typed.hh"
#include "lmdb-safe.hh"
#include "pdns/dns_random.hh"

LmdbId MDBGetMaxID(MDBRWTransaction& txn, MDBDbi& dbi)
{
  auto cursor = txn->getRWCursor(dbi);
  MDBOutVal maxidval{};
  MDBOutVal maxcontent{};
  LmdbId maxid{0};
  if (cursor.get(maxidval, maxcontent, MDB_LAST) == 0) {
    maxid = static_cast<LmdbId>(maxidval.getNoStripHeader<LmdbSerializedId>());
  }
  return maxid;
}

LmdbId MDBGetRandomID(MDBRWTransaction& txn, MDBDbi& dbi)
{
  auto cursor = txn->getRWCursor(dbi);
  LmdbId newID = 0;
  for (int attempts = 0; attempts < 20; attempts++) {
    MDBOutVal key{};
    MDBOutVal content{};

    // dns_random generates a random number in [0..signed_int_max-1]. We add 1 to avoid 0
    // and allow type_max. 0 is avoided because the put() interface uses it to mean
    // "please allocate a number for me".
    newID = dns_random(std::numeric_limits<signed int>::max()) + 1;
    if (cursor.find(MDBInVal(uint32to128(newID)), key, content) != 0) {
      return newID;
    }
  }
  throw std::runtime_error("MDBGetRandomID() could not assign an unused random ID");
}
