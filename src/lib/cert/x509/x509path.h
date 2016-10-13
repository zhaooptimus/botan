/*
* X.509 Cert Path Validation
* (C) 2010-2011 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_X509_CERT_PATH_VALIDATION_H__
#define BOTAN_X509_CERT_PATH_VALIDATION_H__

#include <botan/cert_status.h>
#include <botan/x509cert.h>
#include <botan/certstor.h>
#include <botan/ocsp.h>
#include <future>
#include <functional>
#include <set>

namespace Botan {

/**
* Specifies restrictions on the PKIX path validation
*/
class BOTAN_DLL Path_Validation_Restrictions
   {
   public:
      /**
      * @param require_rev if true, revocation information is required
      * @param minimum_key_strength is the minimum strength (in terms of
      *        operations, eg 80 means 2^80) of a signature. Signatures
      *        weaker than this are rejected. If more than 80, SHA-1
      *        signatures are also rejected.
      * @param ocsp_all_intermediates
      */
      Path_Validation_Restrictions(bool require_rev = false,
                                   size_t minimum_key_strength = 80,
                                   bool ocsp_all_intermediates = false);

      /**
      * @param require_rev if true, revocation information is required
      * @param minimum_key_strength is the minimum strength (in terms of
      *        operations, eg 80 means 2^80) of a signature. Signatures
      *        weaker than this are rejected.
      * @param ocsp_all_intermediates
      * @param trusted_hashes a set of trusted hashes. Any signatures
      *        created using a hash other than one of these will be
      *        rejected.
      */
      Path_Validation_Restrictions(bool require_rev,
                                   size_t minimum_key_strength,
                                   bool ocsp_all_intermediates,
                                   const std::set<std::string>& trusted_hashes) :
         m_require_revocation_information(require_rev),
         m_ocsp_all_intermediates(ocsp_all_intermediates),
         m_trusted_hashes(trusted_hashes),
         m_minimum_key_strength(minimum_key_strength) {}

      /**
      * @return whether revocation information is required
      */
      bool require_revocation_information() const
         { return m_require_revocation_information; }

      /**
      * FIXME add doc
      */
      bool ocsp_all_intermediates() const
         { return m_ocsp_all_intermediates; }

      /**
      * @return trusted signature hash functions
      */
      const std::set<std::string>& trusted_hashes() const
         { return m_trusted_hashes; }

      /**
      * @return minimum required key strength
      */
      size_t minimum_key_strength() const
         { return m_minimum_key_strength; }

   private:
      bool m_require_revocation_information;
      bool m_ocsp_all_intermediates;
      std::set<std::string> m_trusted_hashes;
      size_t m_minimum_key_strength;
   };

/**
* Represents the result of a PKIX path validation
*/
class BOTAN_DLL Path_Validation_Result
   {
   public:
      typedef Certificate_Status_Code Code;

      /**
      * @return the set of hash functions you are implicitly
      * trusting by trusting this result.
      */
      std::set<std::string> trusted_hashes() const;

      /**
      * @return the trust root of the validation if successful
      * throws an exception if the validation failed
      */
      const X509_Certificate& trust_root() const;

      /**
      * @return the full path from subject to trust root
      */
      const std::vector<std::shared_ptr<const X509_Certificate>>& cert_path() const { return m_cert_path; }

      /**
      * @return true iff the validation was successful
      */
      bool successful_validation() const;

      /**
      * @return overall validation result code
      */
      Certificate_Status_Code result() const { return m_overall; }

      /**
      * @return a set of status codes for each certificate in the chain
      */
      const std::vector<std::set<Certificate_Status_Code>>& all_statuses() const
         { return m_all_status; }

      /**
      * @return string representation of the validation result
      */
      std::string result_string() const;

      /**
      * @param validation status code
      * @return corresponding validation status message
      */
      static const char* status_string(Certificate_Status_Code code);

      /**
      * Create a Path_Validation_Result
      * @param status list of validation status codes
      * @param cert_chain the certificate chain that was validated
      */
      Path_Validation_Result(std::vector<std::set<Certificate_Status_Code>> status,
                             std::vector<std::shared_ptr<const X509_Certificate>>&& cert_chain);

      /**
      * Create a Path_Validation_Result
      * @status status validation status code
      */
      explicit Path_Validation_Result(Certificate_Status_Code status) : m_overall(status) {}

   private:
      friend Path_Validation_Result BOTAN_DLL x509_path_validate(
         const std::vector<X509_Certificate>& end_certs,
         const Path_Validation_Restrictions& restrictions,
         const std::vector<Certificate_Store*>& certstores);

      Certificate_Status_Code m_overall;
      std::vector<std::set<Certificate_Status_Code>> m_all_status;
      std::vector<std::shared_ptr<const X509_Certificate>> m_cert_path;
   };

typedef std::function<std::future<OCSP::Response>
                      (const X509_Certificate&,
                       const X509_Certificate&,
                       const Certificate_Store&)>
   OCSP_request_fn;

BOTAN_DLL std::future<OCSP::Response>
online_ocsp_check(const X509_Certificate& subject,
                  const X509_Certificate& issuer,
                  const Certificate_Store& trusted_roots);

/**
* PKIX Path Validation
* @param end_certs a chain of certs starting with the end entity
* @param restrictions any restrictions on the validation process
* @param certstores trusted certificates
* @param hostname the expected hostname of the end entity
* @param usage what this certificate is to be used for
* @param ocsp_check is a callback requesting an OCSP check be issued,
*        default online_ocsp_check opens socket in a new thread.
*/
Path_Validation_Result BOTAN_DLL x509_path_validate(
   const std::vector<X509_Certificate>& end_certs,
   const Path_Validation_Restrictions& restrictions,
   const std::vector<Certificate_Store*>& certstores,
   const std::string& hostname = "",
   Usage_Type usage = Usage_Type::UNSPECIFIED,
   OCSP_request_fn ocsp_check = online_ocsp_check);

/**
* PKIX Path Validation
* @param end_cert certificate to validate
* @param restrictions path validation restrictions
* @param certstores list of stores that contain trusted certificates
* @param hostname if not empty, compared against the DNS name in end_cert
* @param usage if not set to UNSPECIFIED, compared against the key usage in end_cert
* @return result of the path validation
*/
inline Path_Validation_Result x509_path_validate(
   const X509_Certificate& end_cert,
   const Path_Validation_Restrictions& restrictions,
   const std::vector<Certificate_Store*>& certstores,
   const std::string& hostname = "",
   Usage_Type usage = Usage_Type::UNSPECIFIED,
   OCSP_request_fn ocsp = online_ocsp_check)
   {
   std::vector<X509_Certificate> end_certs;
   end_certs.push_back(end_cert);
   return x509_path_validate(end_certs, restrictions, certstores, hostname, usage, ocsp);
   }

/**
* PKIX Path Validation
* @param end_cert certificate to validate
* @param restrictions path validation restrictions
* @param store store that contains trusted certificates
* @param hostname if not empty, compared against the DNS name in end_cert
* @param usage if not set to UNSPECIFIED, compared against the key usage in end_cert
* @return result of the path validation
*/
inline Path_Validation_Result x509_path_validate(
   const X509_Certificate& end_cert,
   const Path_Validation_Restrictions& restrictions,
   const Certificate_Store& store,
   const std::string& hostname = "",
   Usage_Type usage = Usage_Type::UNSPECIFIED,
   OCSP_request_fn ocsp = online_ocsp_check)
   {
   std::vector<X509_Certificate> end_certs;
   end_certs.push_back(end_cert);

   std::vector<Certificate_Store*> certstores;
   certstores.push_back(const_cast<Certificate_Store*>(&store));
   return x509_path_validate(end_certs, restrictions, certstores, hostname, usage, ocsp);
   }

/**
* PKIX Path Validation
* @param end_certs certificate chain to validate
* @param restrictions path validation restrictions
* @param store store that contains trusted certificates
* @param hostname if not empty, compared against the DNS name in end_certs[0]
* @param usage if not set to UNSPECIFIED, compared against the key usage in end_certs[0]
* @return result of the path validation
*/
inline Path_Validation_Result x509_path_validate(
   const std::vector<X509_Certificate>& end_certs,
   const Path_Validation_Restrictions& restrictions,
   const Certificate_Store& store,
   const std::string& hostname = "",
   Usage_Type usage = Usage_Type::UNSPECIFIED,
   OCSP_request_fn ocsp = online_ocsp_check)
   {
   std::vector<Certificate_Store*> certstores;
   certstores.push_back(const_cast<Certificate_Store*>(&store));

   return x509_path_validate(end_certs, restrictions, certstores, hostname, usage, ocsp);
   }

}

#endif
