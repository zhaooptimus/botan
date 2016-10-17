/*
* Interface for AEAD modes
* (C) 2013 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_AEAD_MODE_H__
#define BOTAN_AEAD_MODE_H__

#include <botan/cipher_mode.h>

namespace Botan {

/**
* Interface for AEAD (Authenticated Encryption with Associated Data)
* modes. These modes provide both encryption and message
* authentication, and can authenticate additional per-message data
* which is not included in the ciphertext (for instance a sequence
* number).
*/
class BOTAN_DLL AEAD_Mode : public Cipher_Mode
   {
   public:
      bool authenticated() const override { return true; }

      /**
      * Set associated data that is not included in the ciphertext but
      * that should be authenticated. Must be called after set_key and
      * before start.
      *
      * Unless reset by another call, the associated data is kept
      * between messages. Thus, if the AD does not change, calling
      * once (after set_key) is the optimum.
      *
      * @param ad the associated data
      * @param ad_len length of add in bytes
      */
      virtual void set_associated_data(const byte ad[], size_t ad_len) = 0;

      template<typename Alloc>
      void set_associated_data_vec(const std::vector<byte, Alloc>& ad)
         {
         set_associated_data(ad.data(), ad.size());
         }

      template<typename Alloc>
      void set_ad(const std::vector<byte, Alloc>& ad)
         {
         set_associated_data(ad.data(), ad.size());
         }

      /**
      * Default AEAD nonce size (a commonly supported value among AEAD
      * modes, and large enough that random collisions are unlikely).
      */
      size_t default_nonce_length() const override { return 12; }

      virtual ~AEAD_Mode() {}
   };

/**
* Get an AEAD mode by name (eg "AES-128/GCM" or "Serpent/EAX")
*/
inline AEAD_Mode* get_aead(const std::string& name, Cipher_Dir direction)
   {
   std::unique_ptr<Cipher_Mode> mode(get_cipher_mode(algo_spec, direction));

   if(AEAD_Mode* aead = dynamic_cast<AEAD_Mode*>(mode.get()))
      {
      mode.release();
      return aead;
      }

   return nullptr;
   }

}

#endif
