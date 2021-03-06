/*
* Certificate Store
* (C) 1999-2010,2013 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CERT_STORE_H__
#define BOTAN_CERT_STORE_H__

#include <botan/x509cert.h>
#include <botan/x509_crl.h>

namespace Botan {

/**
* Certificate Store Interface
*/
class BOTAN_DLL Certificate_Store
   {
   public:
      virtual ~Certificate_Store() {}

      /**
      * Find a certificate by Subject DN and (optionally) key identifier
      * @param subject_dn the subject's distinguished name
      * @param key_id an optional key id
      * @return a matching certificate or nullptr otherwise
      */
      virtual std::shared_ptr<const X509_Certificate>
         find_cert(const X509_DN& subject_dn, const std::vector<byte>& key_id) const = 0;

      /**
      * Finds a CRL for the given certificate
      * @param subject the subject certificate
      * @return the CRL for subject or nullptr otherwise
      */
      virtual std::shared_ptr<const X509_CRL> find_crl_for(const X509_Certificate& subject) const;

      /**
      * @return whether the certificate is known
      * @param cert certififcate to be searched
      */
      bool certificate_known(const X509_Certificate& cert) const
         {
         return find_cert(cert.subject_dn(), cert.subject_key_id()) != nullptr;
         }

      // remove this (used by TLS::Server)
      virtual std::vector<X509_DN> all_subjects() const = 0;
   };

/**
* In Memory Certificate Store
*/
class BOTAN_DLL Certificate_Store_In_Memory : public Certificate_Store
   {
   public:
      /**
      * Attempt to parse all files in dir (including subdirectories)
      * as certificates. Ignores errors.
      */
      explicit Certificate_Store_In_Memory(const std::string& dir);

      /**
      * Adds given certificate to the store.
      */
      explicit Certificate_Store_In_Memory(const X509_Certificate& cert);

      /**
      * Create an empty store.
      */
      Certificate_Store_In_Memory() {}

      /**
      * Add a certificate to the store.
      * @param cert certificate to be added
      */
      void add_certificate(const X509_Certificate& cert);

      /**
      * Add a certificate revocation list (CRL) to the store.
      * @param crl CRL to be added
      */
      void add_crl(const X509_CRL& crl);

      /**
      * @return DNs for all certificates managed by the store
      */
      std::vector<X509_DN> all_subjects() const override;

      /*
      * Find a certificate by Subject DN and (optionally) key identifier
      */
      std::shared_ptr<const X509_Certificate> find_cert(
         const X509_DN& subject_dn,
         const std::vector<byte>& key_id) const override;

      /**
      * Finds a CRL for the given certificate
      */
      std::shared_ptr<const X509_CRL> find_crl_for(const X509_Certificate& subject) const override;
   private:
      // TODO: Add indexing on the DN and key id to avoid linear search
      std::vector<std::shared_ptr<X509_Certificate>> m_certs;
      std::vector<std::shared_ptr<X509_CRL>> m_crls;
   };

/**
* FIXME add doc
*/
class BOTAN_DLL Certificate_Store_Overlay : public Certificate_Store
   {
   public:
      explicit Certificate_Store_Overlay(const std::vector<std::shared_ptr<const X509_Certificate>>& certs) :
         m_certs(certs) {}

      /**
      * @return DNs for all certificates managed by the store
      */
      std::vector<X509_DN> all_subjects() const override;

      /**
      * Find a certificate by Subject DN and (optionally) key identifier
      */
      std::shared_ptr<const X509_Certificate> find_cert(
         const X509_DN& subject_dn,
         const std::vector<byte>& key_id) const override;
   private:
      const std::vector<std::shared_ptr<const X509_Certificate>>& m_certs;
   };

}
#endif
