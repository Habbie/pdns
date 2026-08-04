#include "dns_random.hh"
#include <string>
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "dnssecinfra.hh"
#include "dnssec.hh"

constexpr unsigned int PRIVATEDNS = 253;
inline unsigned int TestingAlgo(uint8_t num) { return (num << 8) + PRIVATEDNS; }

class OneTwoKDNSCryptoKeyEngine : public DNSCryptoKeyEngine
{
public:
  explicit OneTwoKDNSCryptoKeyEngine(Logr::log_t slog, unsigned int algo) :
    DNSCryptoKeyEngine(slog, algo)
  {}
  [[nodiscard]] string getName() const override { return "Testing Algorithm Signers dispatcher"; }
  void create(unsigned int bits) override;

  /**
   * \brief Creates a key engine from a PEM file.
   *
   * Receives an open file handle with PEM contents and creates an key engine.
   *
   * \param[in] drc Key record contents to be populated.
   *
   * \param[in] inputFile An open file handle to a file containing PEM contents.
   *
   * \param[in] filename Only used for providing filename information in error messages.
   *
   * \return A key engine populated with the contents of the PEM file.
   */
  // void createFromPEMFile(DNSKEYRecordContent& drc, std::FILE& inputFile, std::optional<std::reference_wrapper<const std::string>> filename = std::nullopt) override;

  /**
   * \brief Writes this key's contents to a file.
   *
   * Receives an open file handle and writes this key's contents to the
   * file.
   *
   * \param[in] outputFile An open file handle for writing.
   *
   * \exception std::runtime_error In case of OpenSSL errors.
   */
  // void convertToPEMFile(std::FILE& outputFile) const override;

  [[nodiscard]] storvector_t convertToISCVector() const override;
  [[nodiscard]] std::string sign(const std::string& msg) const override;
  [[nodiscard]] bool verify(const std::string& msg, const std::string& signature) const override;
  [[nodiscard]] std::string getPublicKeyString() const override;
  [[nodiscard]] int getBits(bool forTest = false) const override;
  [[nodiscard]] int getBytes(void) const; // not from parent class
  void fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap) override;
  void fromPublicKeyString(const std::string& input) override;

  static std::unique_ptr<DNSCryptoKeyEngine> maker(Logr::log_t slog, unsigned int algorithm)
  {
    return make_unique<OneTwoKDNSCryptoKeyEngine>(slog, algorithm);
  }

private:
  std::string d_seckey;
  std::string d_pubkey;
};

void OneTwoKDNSCryptoKeyEngine::create(unsigned int bits)
{
  if (bits != getBits()) {
    throw runtime_error("Unsupported key length of " + std::to_string(bits) + " bits requested, OneTwoK signer class");
  }

  // these strings must all be the same length, and that length must be a divisor of 1024 and 2048
  std::vector<std::string> words = {
    "Implored",
    "Outreach",
    "Ceilings",
    "Impurely",
    "Musicale",
    "Stricter",
    "Obstacle",
    "Majestic",
  };

  d_seckey.resize(0);

  while (d_pubkey.length() < getBytes()) {
    d_pubkey.append(words[dns_random(words.size())]);
  }

  d_seckey = d_pubkey;
  std::reverse(d_seckey.begin(), d_seckey.end());
}

int OneTwoKDNSCryptoKeyEngine::getBytes(void) const
{
  switch(d_algorithm >> 8) {
  case '1':
    return 1024;
  case '2':
    return 2048;
  default:
    throw runtime_error("invalid algorithm number for OneTwoK class");
  }
}


int OneTwoKDNSCryptoKeyEngine::getBits(bool /* forTest */) const
{
  return getBytes() * 8;
}

DNSCryptoKeyEngine::storvector_t OneTwoKDNSCryptoKeyEngine::convertToISCVector() const
{
  /*
    Private-key-format: v1.2
    Algorithm: 13053 (0x32FD)
  */

  storvector_t storvector;
  string algorithm = "253 (\"" + std::string(1, char(d_algorithm >> 8)) + ".\", " + std::to_string(getBytes()) + " bytes)";

  storvector.emplace_back("Algorithm", algorithm);

  storvector.emplace_back("PrivateKey", d_seckey);

  return storvector;
}

void OneTwoKDNSCryptoKeyEngine::fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap)
{
  /*
    Private-key-format: v1.2
    Algorithm: 13053 (0x32FD)
  */

  pdns::checked_stoi_into(drc.d_algorithm, stormap["algorithm"]);

  d_seckey = stormap["privatekey"];
  if (d_seckey.length() != getBytes()) {
    throw runtime_error("Key size mismatch in ISCMap, OneTwoK class");
  }

  d_pubkey = d_seckey;
  std::reverse(d_pubkey.begin(), d_pubkey.end());
}

std::string OneTwoKDNSCryptoKeyEngine::getPublicKeyString() const
{
  return d_pubkey;
}

void OneTwoKDNSCryptoKeyEngine::fromPublicKeyString(const std::string& input)
{
  if (input.length() != getBytes()) {
    throw runtime_error("Public key size mismatch, OneTwoKDNS class");
  }

  d_pubkey = input;
}

std::string OneTwoKDNSCryptoKeyEngine::sign(const std::string& /* msg */) const
{
  return d_pubkey;
}

bool OneTwoKDNSCryptoKeyEngine::verify(const std::string& /* msg */, const std::string& signature) const
{
  return signature.length() == getBytes();
}

class TestingDNSCryptoKeyEngineDispatcher : public DNSCryptoKeyEngine
{
public:
  explicit TestingDNSCryptoKeyEngineDispatcher(Logr::log_t slog, unsigned int algo) :
    DNSCryptoKeyEngine(slog, algo)
  {}
  explicit TestingDNSCryptoKeyEngineDispatcher(Logr::log_t slog, unsigned int algo, std::unique_ptr<DNSCryptoKeyEngine> dcke) :
    DNSCryptoKeyEngine(slog, algo), d_dcke(std::move(dcke))
  {}
  [[nodiscard]] string getName() const override { return "Testing Algorithm Signers dispatcher"; }
  void create(unsigned int bits) override {
    d_dcke->create(bits);
  }

  /**
   * \brief Creates a key engine from a PEM file.
   *
   * Receives an open file handle with PEM contents and creates an key engine.
   *
   * \param[in] drc Key record contents to be populated.
   *
   * \param[in] inputFile An open file handle to a file containing PEM contents.
   *
   * \param[in] filename Only used for providing filename information in error messages.
   *
   * \return A key engine populated with the contents of the PEM file.
   */
  // void createFromPEMFile(DNSKEYRecordContent& drc, std::FILE& inputFile, std::optional<std::reference_wrapper<const std::string>> filename = std::nullopt) override;

  /**
   * \brief Writes this key's contents to a file.
   *
   * Receives an open file handle and writes this key's contents to the
   * file.
   *
   * \param[in] outputFile An open file handle for writing.
   *
   * \exception std::runtime_error In case of OpenSSL errors.
   */
  // void convertToPEMFile(std::FILE& outputFile) const override;

  [[nodiscard]] storvector_t convertToISCVector() const override {
    return d_dcke->convertToISCVector();
  };
  [[nodiscard]] std::string sign(const std::string& msg) const override {
    auto ret = d_dcke->sign(msg);
    return DNSName("2.").toDNSString() + ret;
  };
  [[nodiscard]] bool verify(const std::string& msg, const std::string& signature) const override {
    return d_dcke->verify(msg, signature.substr(3, std::string::npos));
  };
  [[nodiscard]] std::string getPublicKeyString() const override {
    return DNSName("2.").toDNSString() + d_dcke->getPublicKeyString();
  };
  [[nodiscard]] int getBits(bool forTest = false) const override {
    return d_dcke->getBits(forTest);
  };
  void fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap) override {
    d_dcke->fromISCMap(drc, stormap);
  };
  void fromPublicKeyString(const std::string& content) override {
    d_dcke->fromPublicKeyString(content.substr(3, std::string::npos));
  };

  static std::unique_ptr<DNSCryptoKeyEngine> maker(Logr::log_t slog, unsigned int algorithm)
  {
    algorithm = algorithm + ('2' << 8);
    return make_unique<TestingDNSCryptoKeyEngineDispatcher>(slog, algorithm, DNSCryptoKeyEngine::make(slog, algorithm));
    // return make_unique<TwoKDNSCryptoKeyEngine>(slog, algorithm);
  }

private:
  std::unique_ptr<DNSCryptoKeyEngine> d_dcke;
};

namespace
{
const struct LoaderSillySignersStruct
{
  LoaderSillySignersStruct()
  {
    DNSCryptoKeyEngine::report(PRIVATEDNS, &TestingDNSCryptoKeyEngineDispatcher::maker);
    DNSCryptoKeyEngine::report(TestingAlgo('1'), &OneTwoKDNSCryptoKeyEngine::maker);
    DNSCryptoKeyEngine::report(TestingAlgo('2'), &OneTwoKDNSCryptoKeyEngine::maker);
  }
} loadersillysigners;
}
