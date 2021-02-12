#pragma once

// #include "dnsparser.hh" // FIXME: remove this when done

class NSECBitmap
{
public:
  NSECBitmap(): d_bitset(nullptr)
  {
  }
  NSECBitmap(const NSECBitmap& rhs): d_set(rhs.d_set)
  {
    if (rhs.d_bitset) {
      d_bitset = std::unique_ptr<std::bitset<nbTypes>>(new std::bitset<nbTypes>(*(rhs.d_bitset)));
    }
  }
  NSECBitmap& operator=(const NSECBitmap& rhs)
  {
    d_set = rhs.d_set;

    if (rhs.d_bitset) {
      d_bitset = std::unique_ptr<std::bitset<nbTypes>>(new std::bitset<nbTypes>(*(rhs.d_bitset)));
    }

    return *this;
  }
  NSECBitmap(NSECBitmap&& rhs): d_bitset(std::move(rhs.d_bitset)), d_set(std::move(rhs.d_set))
  {
  }
  bool isSet(uint16_t type) const
  {
    if (d_bitset) {
      return d_bitset->test(type);
    }
    return d_set.count(type);
  }
  void set(uint16_t type)
  {
    if (!d_bitset) {
      if (d_set.size() >= 200) {
        migrateToBitSet();
      }
    }
    if (d_bitset) {
      d_bitset->set(type);
    }
    else {
      d_set.insert(type);
    }
  }
  size_t count() const
  {
    if (d_bitset) {
      return d_bitset->count();
    }
    else {
      return d_set.size();
    }
  }

  // void fromPacket(PacketReader& pr);
  // void toPacket(DNSPacketWriter& pw);
  std::string getZoneRepresentation() const;

  static constexpr size_t const nbTypes = 65536;

// private:

  void migrateToBitSet()
  {
    d_bitset = std::unique_ptr<std::bitset<nbTypes>>(new std::bitset<nbTypes>());
    for (const auto& type : d_set) {
      d_bitset->set(type);
    }
    d_set.clear();
  }
  /* using a dynamic set is very efficient for a small number of
     types covered (~200), but uses a lot of memory (up to 3MB)
     when there are a lot of them.
     So we start with the set, but allocate and switch to a bitset
     if the number of covered types increases a lot */
  std::unique_ptr<std::bitset<nbTypes>> d_bitset;
  std::set<uint16_t> d_set;
};

