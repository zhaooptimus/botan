/*
* PK Key Types
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PK_KEYS_H__
#define BOTAN_PK_KEYS_H__

#include <botan/secmem.h>
#include <botan/asn1_oid.h>
#include <botan/alg_id.h>
#include <botan/rng.h>

namespace Botan {

class RandomNumberGenerator;

namespace PK_Ops {

class Encryption;
class Decryption;
class Key_Agreement;
class KEM_Encryption;
class KEM_Decryption;
class Verification;
class Signature;

}

/**
* Public Key Base Class.
*/
class BOTAN_DLL Public_Key
   {
   public:
      virtual ~Public_Key() {}

      /**
      * Get the name of the underlying public key scheme.
      * @return name of the public key scheme
      */
      virtual std::string algo_name() const = 0;

      /**
      * Return the estimated strength of the underlying key against
      * the best currently known attack. Note that this ignores anything
      * but pure attacks against the key itself and do not take into
      * account padding schemes, usage mistakes, etc which might reduce
      * the strength. However it does suffice to provide an upper bound.
      *
      * @return estimated strength in bits
      */
      virtual size_t estimated_strength() const = 0;

      /**
      * Get the OID of the underlying public key scheme.
      * @return OID of the public key scheme
      */
      virtual OID get_oid() const;

      /**
      * Test the key values for consistency.
      * @param rng rng to use
      * @param strong whether to perform strong and lengthy version
      * of the test
      * @return true if the test is passed
      */
      virtual bool check_key(RandomNumberGenerator& rng,
                             bool strong) const = 0;

      /**
      * Find out the number of message parts supported by this scheme.
      * @return number of message parts
      */
      virtual size_t message_parts() const { return 1; }

      /**
      * Find out the message part size supported by this scheme/key.
      * @return size of the message parts in bits
      */
      virtual size_t message_part_size() const { return 0; }

      /**
      * Get the maximum message size in bits supported by this public key.
      * @return maximum message size in bits
      */
      virtual size_t max_input_bits() const = 0;

      /**
      * @return X.509 AlgorithmIdentifier for this key
      */
      virtual AlgorithmIdentifier algorithm_identifier() const = 0;

      /**
      * @return X.509 subject key encoding for this key object
      */
      virtual std::vector<byte> x509_subject_public_key() const = 0;

      // Internal or non-public declarations follow

      /**
      * This is an internal library function exposed on key types.
      * In almost all cases applications should use wrappers in pubkey.h
      *
      * Return an encryption operation for this key/params or throw
      *
      * @param rng a random number generator. The PK_Op may maintain a
      * reference to the RNG and use it many times. The rng must outlive
      * any operations which reference it.
      */
      virtual std::unique_ptr<PK_Ops::Encryption>
         create_encryption_op(RandomNumberGenerator& rng,
                              const std::string& params,
                              const std::string& provider) const;

      /**
      * This is an internal library function exposed on key types.
      * In almost all cases applications should use wrappers in pubkey.h
      *
      * Return a KEM encryption operation for this key/params or throw
      *
      * @param rng a random number generator. The PK_Op may maintain a
      * reference to the RNG and use it many times. The rng must outlive
      * any operations which reference it.
      */
      virtual std::unique_ptr<PK_Ops::KEM_Encryption>
         create_kem_encryption_op(RandomNumberGenerator& rng,
                                  const std::string& params,
                                  const std::string& provider) const;

      /**
      * This is an internal library function exposed on key types.
      * In almost all cases applications should use wrappers in pubkey.h
      *
      * Return a verification operation for this key/params or throw
      */
      virtual std::unique_ptr<PK_Ops::Verification>
         create_verification_op(const std::string& params,
                                const std::string& provider) const;

   protected:
      /**
      * Self-test after loading a key
      * @param rng a random number generator
      */
      virtual void load_check(RandomNumberGenerator& rng) const;
   };

/**
* Private Key Base Class
*/
class BOTAN_DLL Private_Key : public virtual Public_Key
   {
   public:
      /**
      * @return PKCS #8 private key encoding for this key object
      */
      virtual secure_vector<byte> pkcs8_private_key() const = 0;

      /**
      * @return PKCS #8 AlgorithmIdentifier for this key
      * Might be different from the X.509 identifier, but normally is not
      */
      virtual AlgorithmIdentifier pkcs8_algorithm_identifier() const
         { return algorithm_identifier(); }

      // Internal or non-public declarations follow

      /**
       * @return Hash of the PKCS #8 encoding for this key object
       */
      std::string fingerprint(const std::string& alg = "SHA") const;

      /**
      * This is an internal library function exposed on key types.
      * In almost all cases applications should use wrappers in pubkey.h
      *
      * Return an decryption operation for this key/params or throw
      *
      * @param rng a random number generator. The PK_Op may maintain a
      * reference to the RNG and use it many times. The rng must outlive
      * any operations which reference it.
      */
      virtual std::unique_ptr<PK_Ops::Decryption>
         create_decryption_op(RandomNumberGenerator& rng,
                              const std::string& params,
                              const std::string& provider) const;

      /**
      * This is an internal library function exposed on key types.
      * In almost all cases applications should use wrappers in pubkey.h
      *
      * Return a KEM decryption operation for this key/params or throw
      *
      * @param rng a random number generator. The PK_Op may maintain a
      * reference to the RNG and use it many times. The rng must outlive
      * any operations which reference it.
      */
      virtual std::unique_ptr<PK_Ops::KEM_Decryption>
         create_kem_decryption_op(RandomNumberGenerator& rng,
                                  const std::string& params,
                                  const std::string& provider) const;

      /**
      * This is an internal library function exposed on key types.
      * In almost all cases applications should use wrappers in pubkey.h
      *
      * Return a signature operation for this key/params or throw
      *
      * @param rng a random number generator. The PK_Op may maintain a
      * reference to the RNG and use it many times. The rng must outlive
      * any operations which reference it.
      */
      virtual std::unique_ptr<PK_Ops::Signature>
         create_signature_op(RandomNumberGenerator& rng,
                             const std::string& params,
                             const std::string& provider) const;

      /**
      * This is an internal library function exposed on key types.
      * In almost all cases applications should use wrappers in pubkey.h
      *
      * Return a key agreement operation for this key/params or throw
      *
      * @param rng a random number generator. The PK_Op may maintain a
      * reference to the RNG and use it many times. The rng must outlive
      * any operations which reference it.
      */
      virtual std::unique_ptr<PK_Ops::Key_Agreement>
         create_key_agreement_op(RandomNumberGenerator& rng,
                                 const std::string& params,
                                 const std::string& provider) const;

   protected:
      /**
      * Self-test after loading a key
      * @param rng a random number generator
      */
      void load_check(RandomNumberGenerator& rng) const override;

      /**
      * Self-test after generating a key
      * @param rng a random number generator
      */
      void gen_check(RandomNumberGenerator& rng) const;
   };

/**
* PK Secret Value Derivation Key
*/
class BOTAN_DLL PK_Key_Agreement_Key : public virtual Private_Key
   {
   public:
      /*
      * @return public component of this key
      */
      virtual std::vector<byte> public_value() const = 0;

      virtual ~PK_Key_Agreement_Key() {}
   };

/*
* Old compat typedefs
* TODO: remove these?
*/
typedef PK_Key_Agreement_Key PK_KA_Key;
typedef Public_Key X509_PublicKey;
typedef Private_Key PKCS8_PrivateKey;

}

#endif
