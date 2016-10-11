/*
* OpenSSL Hash Functions
* (C) 1999-2007,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/hash.h>
#include <botan/internal/openssl.h>
#include <openssl/evp.h>

namespace Botan {

namespace {

class OpenSSL_HashFunction : public HashFunction
   {
   public:
      void clear() override
         {
         const EVP_MD* algo = EVP_MD_CTX_md(&m_md);
         EVP_DigestInit_ex(&m_md, algo, nullptr);
         }

      std::string provider() const override { return "openssl"; }
      std::string name() const override { return m_name; }

      HashFunction* clone() const override
         {
         const EVP_MD* algo = EVP_MD_CTX_md(&m_md);
         return new OpenSSL_HashFunction(algo, name());
         }

      size_t output_length() const override
         {
         return EVP_MD_size(EVP_MD_CTX_md(&m_md));
         }

      size_t hash_block_size() const override
         {
         return EVP_MD_block_size(EVP_MD_CTX_md(&m_md));
         }

      OpenSSL_HashFunction(const EVP_MD* md, const std::string& name) : m_name(name)
         {
         EVP_MD_CTX_init(&m_md);
         EVP_DigestInit_ex(&m_md, md, nullptr);
         }

      ~OpenSSL_HashFunction()
         {
         EVP_MD_CTX_cleanup(&m_md);
         }

   private:
      void add_data(const byte input[], size_t length) override
         {
         EVP_DigestUpdate(&m_md, input, length);
         }

      void final_result(byte output[]) override
         {
         EVP_DigestFinal_ex(&m_md, output, nullptr);
         const EVP_MD* algo = EVP_MD_CTX_md(&m_md);
         EVP_DigestInit_ex(&m_md, algo, nullptr);
         }

      std::string m_name;
      EVP_MD_CTX m_md;
   };

}

std::unique_ptr<HashFunction>
make_openssl_hash(const std::string& name)
   {
   static const std::map<std::string, const EVP_MD*> s_hash_evps = {
#if defined(BOTAN_HAS_SHA1) && !defined(OPENSSL_NO_SHA)
      { "SHA-160", EVP_sha1() },
#endif

#if defined(BOTAN_HAS_SHA2_32) && !defined(OPENSSL_NO_SHA256)
      { "SHA-224", EVP_sha224() },
      { "SHA-256", EVP_sha256() },
#endif

#if defined(BOTAN_HAS_SHA2_64) && !defined(OPENSSL_NO_SHA512)
      { "SHA-384", EVP_sha384() },
      { "SHA-512", EVP_sha512() },
#endif

#if defined(BOTAN_HAS_MD4) && !defined(OPENSSL_NO_MD4)
      { "MD4", EVP_md4() },
#endif

#if defined(BOTAN_HAS_MD5) && !defined(OPENSSL_NO_MD5)
      { "MD5", EVP_md5() },
#endif

#if defined(BOTAN_HAS_RIPEMD_160) && !defined(OPENSSL_NO_RIPEMD)
      { "RIPEMD-160", EVP_ripemd160() },
#endif
   };

   auto i = s_hash_evps.find(name);
   if(i != s_hash_evps.end())
      {
      return std::unique_ptr<HashFunction>(new OpenSSL_HashFunction(i->second, i->first));
      }

   throw Lookup_Error("No OpenSSL support for hash " + name);
   }

}
