/*
* Cipher Modes
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/cipher_mode.h>
#include <botan/stream_mode.h>
#include <sstream>

#if defined(BOTAN_HAS_MODE_ECB)
  #include <botan/ecb.h>
#endif

#if defined(BOTAN_HAS_MODE_CBC)
  #include <botan/cbc.h>
#endif

#if defined(BOTAN_HAS_MODE_CFB)
  #include <botan/cfb.h>
#endif

#if defined(BOTAN_HAS_MODE_XTS)
  #include <botan/xts.h>
#endif

namespace Botan {

#if defined(BOTAN_HAS_MODE_CFB)
BOTAN_REGISTER_BLOCK_CIPHER_MODE_LEN(CFB_Encryption, CFB_Decryption, 0);
#endif

#if defined(BOTAN_HAS_MODE_XTS)
BOTAN_REGISTER_BLOCK_CIPHER_MODE(XTS_Encryption, XTS_Decryption);
#endif

Cipher_Mode* get_cipher_mode(const std::string& algo_spec, Cipher_Dir direction)
   {
   /*
   if(Cipher_Mode* aead = get_aead(algo_spec, direction))
   {
      return aead;
   }
   */
   const char* dir_string = (direction == ENCRYPTION) ? "_Encryption" : "_Decryption";

   SCAN_Name spec(algo_spec, dir_string);

#if defined(BOTAN_HAS_CBC)
   if(spec.algo_name() == "CBC_Encryption")
      {
      std::unique_ptr<BlockCipher> bc(BlockCipher::create(spec.arg(0)));

      if(bc)
         {
         const std::string padding = spec.arg(1, "PKCS7");

         if(padding == "CTS")
            return new CTS_Encryption(bc.release());
         else
            return new CBC_Encryption(bc.release(), get_bc_pad(padding));
         }
      }

   if(spec.algo_name() == "CBC_Decryption")
      {
      std::unique_ptr<BlockCipher> bc(BlockCipher::create(spec.arg(0)));

      if(bc)
         {
         const std::string padding = spec.arg(1, "PKCS7");

         if(padding == "CTS")
            return new CTS_Encryption(bc.release());
         else
            return new CBC_Encryption(bc.release(), get_bc_pad(padding));
         }
      }
#endif

#if defined(BOTAN_HAS_XTS)

#endif

#if defined(BOTAN_HAS_CFB)

#endif

#if defined(BOTAN_HAS_ECB)
   if(spec.algo_name() == "ECB_Encryption")
      {
      std::unique_ptr<BlockCipher> bc(BlockCipher::create(spec.arg(0)));
      std::unique_ptr<BlockCipherModePaddingMethod> pad(get_bc_pad(spec.arg(1, "NoPadding")));
      if(bc && pad)
         return new ECB_Encryption(bc.release(), pad.release());
      }
   if(spec.algo_name() == "ECB_Decryption")
      {
      std::unique_ptr<BlockCipher> bc(BlockCipher::create(spec.arg(0)));
      std::unique_ptr<BlockCipherModePaddingMethod> pad(get_bc_pad(spec.arg(1, "NoPadding")));
      if(bc && pad)
         return new ECB_Decryption(bc.release(), pad.release());
      }
#endif

   const std::vector<std::string> algo_parts = split_on(algo_spec, '/');
   if(algo_parts.size() < 2)
      return nullptr;

   const std::string cipher_name = algo_parts[0];
   const std::vector<std::string> mode_info = parse_algorithm_name(algo_parts[1]);

   if(mode_info.empty())
      return nullptr;

   std::ostringstream alg_args;

   alg_args << '(' << cipher_name;
   for(size_t i = 1; i < mode_info.size(); ++i)
      alg_args << ',' << mode_info[i];
   for(size_t i = 2; i < algo_parts.size(); ++i)
      alg_args << ',' << algo_parts[i];
   alg_args << ')';

   const std::string mode_name = mode_info[0] + alg_args.str();
   const std::string mode_name_directional = mode_info[0] + dir_string + alg_args.str();

   if(auto cipher = get_cipher(mode_name_directional, provider))
      {
      return cipher.release();
      }

   if(auto cipher = get_cipher(mode_name, provider))
      {
      return cipher.release();
      }

   if(auto sc = StreamCipher::create(mode_name, provider))
      {
      return new Stream_Cipher_Mode(sc.release());
      }

   return nullptr;
   }

}
