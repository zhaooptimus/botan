/*
* (C) 2014,2015 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include <vector>
#include <memory>
#include <thread>

#if defined(BOTAN_HAS_TLS)

#include <botan/tls_server.h>
#include <botan/tls_client.h>
#include <botan/tls_handshake_msg.h>
#include <botan/pkcs10.h>
#include <botan/x509self.h>
#include <botan/rsa.h>
#include <botan/x509_ca.h>
#include <botan/auto_rng.h>
#include <botan/hex.h>
#endif


namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_TLS)
class Credentials_Manager_Test : public Botan::Credentials_Manager
   {
   public:
      Credentials_Manager_Test(const Botan::X509_Certificate& server_cert,
                               const Botan::X509_Certificate& ca_cert,
                               Botan::Private_Key* server_key) :
         m_server_cert(server_cert),
         m_ca_cert(ca_cert),
         m_key(server_key)
         {
         std::unique_ptr<Botan::Certificate_Store> store(new Botan::Certificate_Store_In_Memory(m_ca_cert));
         m_stores.push_back(std::move(store));
         m_provides_client_certs = false;
         }

      std::vector<Botan::Certificate_Store*>
      trusted_certificate_authorities(const std::string&,
                                      const std::string&) override
         {
         std::vector<Botan::Certificate_Store*> v;
         for(auto&& store : m_stores)
            v.push_back(store.get());
         return v;
         }

      std::vector<Botan::X509_Certificate> cert_chain(
         const std::vector<std::string>& cert_key_types,
         const std::string& type,
         const std::string&) override
         {
         std::vector<Botan::X509_Certificate> chain;

         if(type == "tls-server" || (type == "tls-client" && m_provides_client_certs))
            {
            bool have_match = false;
            for(size_t i = 0; i != cert_key_types.size(); ++i)
               if(cert_key_types[i] == m_key->algo_name())
                  have_match = true;

            if(have_match)
               {
               chain.push_back(m_server_cert);
               chain.push_back(m_ca_cert);
               }
            }

         return chain;
         }

      Botan::Private_Key* private_key_for(const Botan::X509_Certificate&,
                                          const std::string&,
                                          const std::string&) override
         {
         return m_key.get();
         }

      Botan::SymmetricKey psk(const std::string& type,
                              const std::string& context,
                              const std::string&) override
         {
         if(type == "tls-server" && context == "session-ticket")
            return Botan::SymmetricKey("AABBCCDDEEFF012345678012345678");

         if(context == "server.example.com" && type == "tls-client")
            return Botan::SymmetricKey("20B602D1475F2DF888FCB60D2AE03AFD");

         if(context == "server.example.com" && type == "tls-server")
            return Botan::SymmetricKey("20B602D1475F2DF888FCB60D2AE03AFD");

         throw Test_Error("No PSK set for " + type + "/" + context);
         }

   public:
      Botan::X509_Certificate m_server_cert, m_ca_cert;
      std::unique_ptr<Botan::Private_Key> m_key;
      std::vector<std::unique_ptr<Botan::Certificate_Store>> m_stores;
      bool m_provides_client_certs;
   };

Botan::Credentials_Manager* create_creds(Botan::RandomNumberGenerator& rng,
                                         bool with_client_certs = false)
   {
   std::unique_ptr<Botan::Private_Key> ca_key(new Botan::RSA_PrivateKey(rng, 1024));

   Botan::X509_Cert_Options ca_opts;
   ca_opts.common_name = "Test CA";
   ca_opts.country = "US";
   ca_opts.CA_key(1);

   Botan::X509_Certificate ca_cert =
      Botan::X509::create_self_signed_cert(ca_opts,
                                           *ca_key,
                                           "SHA-256",
                                           rng);

   Botan::Private_Key* server_key = new Botan::RSA_PrivateKey(rng, 1024);

   Botan::X509_Cert_Options server_opts;
   server_opts.common_name = "server.example.com";
   server_opts.country = "US";

   Botan::PKCS10_Request req = Botan::X509::create_cert_req(server_opts,
                                                            *server_key,
                                                            "SHA-256",
                                                            rng);

   Botan::X509_CA ca(ca_cert, *ca_key, "SHA-256", Test::rng());

   auto now = std::chrono::system_clock::now();
   Botan::X509_Time start_time(now);
   typedef std::chrono::duration<int, std::ratio<31556926>> years;
   Botan::X509_Time end_time(now + years(1));

   Botan::X509_Certificate server_cert = ca.sign_request(req,
                                                         rng,
                                                         start_time,
                                                         end_time);

   Credentials_Manager_Test* cmt (new Credentials_Manager_Test(server_cert, ca_cert, server_key));
   cmt->m_provides_client_certs = with_client_certs;
   return cmt;
   }

std::function<void (const byte[], size_t)> queue_inserter(std::vector<byte>& q)
   {
   return [&](const byte buf[], size_t sz) { q.insert(q.end(), buf, buf + sz); };
   }

void print_alert(Botan::TLS::Alert)
   {
   }

void alert_cb_with_data(Botan::TLS::Alert, const byte[], size_t)
   {
   }

Test::Result test_tls_handshake(Botan::TLS::Protocol_Version offer_version,
                                Botan::Credentials_Manager& creds,
                                const Botan::TLS::Policy& client_policy,
                                const Botan::TLS::Policy& server_policy,
                                Botan::RandomNumberGenerator& rng)
   {
   Botan::TLS::Session_Manager_In_Memory server_sessions(rng);
   Botan::TLS::Session_Manager_In_Memory client_sessions(rng);

   Test::Result result(offer_version.to_string());

   result.start_timer();

   for(size_t r = 1; r <= 4; ++r)
      {
      bool handshake_done = false;

      result.test_note("Test round " + std::to_string(r));

      auto handshake_complete = [&](const Botan::TLS::Session& session) -> bool {
         handshake_done = true;

         const std::string session_report =
            "Session established " + session.version().to_string() + " " +
            session.ciphersuite().to_string() + " " +
            Botan::hex_encode(session.session_id());

         result.test_note(session_report);

         if(session.version() != offer_version)
            {
            result.test_failure("Offered " + offer_version.to_string() +
                                " got " + session.version().to_string());
            }

         if(r <= 2)
            return true;
         return false;
      };

      auto next_protocol_chooser = [&](std::vector<std::string> protos) {
         if(r <= 2)
            {
            result.test_eq("protocol count", protos.size(), 2);
            result.test_eq("protocol[0]", protos[0], "test/1");
            result.test_eq("protocol[1]", protos[1], "test/2");
            }
         return "test/3";
      };

      const std::vector<std::string> protocols_offered = { "test/1", "test/2" };

      try
         {
         std::vector<byte> c2s_traffic, s2c_traffic, client_recv, server_recv, client_sent, server_sent;

         std::unique_ptr<Botan::TLS::Callbacks> server_cb(new Botan::TLS::Compat_Callbacks(
                 queue_inserter(s2c_traffic),
                 queue_inserter(server_recv),
                 std::function<void (Botan::TLS::Alert, const byte[], size_t)>(alert_cb_with_data),
                 handshake_complete,
                 nullptr,
                 next_protocol_chooser));

         // TLS::Server object constructed by new constructor using virtual callback interface.
         std::unique_ptr<Botan::TLS::Server> server(
            new Botan::TLS::Server(*server_cb,
                                   server_sessions,
                                   creds,
                                   server_policy,
                                   rng,
                                   false));

         std::unique_ptr<Botan::TLS::Callbacks> client_cb(new Botan::TLS::Compat_Callbacks(
                 queue_inserter(c2s_traffic),
                 queue_inserter(client_recv),
                 std::function<void (Botan::TLS::Alert, const byte[], size_t)>(alert_cb_with_data),
                 handshake_complete));

         // TLS::Client object constructed by new constructor using virtual callback interface.
         std::unique_ptr<Botan::TLS::Client> client(
            new Botan::TLS::Client(*client_cb,
                                   client_sessions,
                                   creds,
                                   client_policy,
                                   rng,
                                   Botan::TLS::Server_Information("server.example.com"),
                                   offer_version,
                                   protocols_offered));

         size_t rounds = 0;

         // Test TLS using both new and legacy constructors.
         for(size_t ctor_sel = 0; ctor_sel < 2; ctor_sel++)
            {
            if(ctor_sel == 1)
               {
               c2s_traffic.clear();
               s2c_traffic.clear();
               server_recv.clear();
               client_recv.clear();
               client_sent.clear();
               server_sent.clear();

               // TLS::Server object constructed by legacy constructor.
               server.reset( 
                  new Botan::TLS::Server(queue_inserter(s2c_traffic),
                                         queue_inserter(server_recv),
                                         alert_cb_with_data, 
                                         handshake_complete,
                                         server_sessions,
                                         creds,
                                         server_policy,
                                         rng,
                                         next_protocol_chooser,
                                         false));

               // TLS::Client object constructed by legacy constructor.
               client.reset( 
                  new Botan::TLS::Client(queue_inserter(c2s_traffic),
                                         queue_inserter(client_recv),
                                         alert_cb_with_data,
                                         handshake_complete,
                                         client_sessions,
                                         creds,
                                         server_policy,
                                         rng,
                                         Botan::TLS::Server_Information("server.example.com"),
                                         offer_version,
                                         protocols_offered));
               }

            while(true)
               {
               ++rounds;

               if(rounds > 25)
                  {
                  if(r <= 2)
                     {
                     result.test_failure("Still here after many rounds, deadlock?");
                     }
                  break;
                  }

               if(handshake_done && (client->is_closed() || server->is_closed()))
                  break;

               if(client->is_active() && client_sent.empty())
                  {
                  // Choose random application data to send
                  const size_t c_len = 1 + ((static_cast<size_t>(rng.next_byte()) << 4) ^ rng.next_byte());
                  client_sent = unlock(rng.random_vec(c_len));

                  size_t sent_so_far = 0;
                  while(sent_so_far != client_sent.size())
                     {
                     const size_t left = client_sent.size() - sent_so_far;
                     const size_t rnd12 = (rng.next_byte() << 4) ^ rng.next_byte();
                     const size_t sending = std::min(left, rnd12);

                     client->send(&client_sent[sent_so_far], sending);
                     sent_so_far += sending;
                     }
                  }

               if(server->is_active() && server_sent.empty())
                  {
                  result.test_eq("server->protocol", server->next_protocol(), "test/3");

                  const size_t s_len = 1 + ((static_cast<size_t>(rng.next_byte()) << 4) ^ rng.next_byte());
                  server_sent = unlock(rng.random_vec(s_len));

                  size_t sent_so_far = 0;
                  while(sent_so_far != server_sent.size())
                     {
                     const size_t left = server_sent.size() - sent_so_far;
                     const size_t rnd12 = (rng.next_byte() << 4) ^ rng.next_byte();
                     const size_t sending = std::min(left, rnd12);

                     server->send(&server_sent[sent_so_far], sending);
                     sent_so_far += sending;
                     }
                  }

               const bool corrupt_client_data = (r == 3);
               const bool corrupt_server_data = (r == 4);

               if(c2s_traffic.size() > 0)
                  {
                  /*
                  * Use this as a temp value to hold the queues as otherwise they
                  * might end up appending more in response to messages during the
                  * handshake.
                  */
                  std::vector<byte> input;
                  std::swap(c2s_traffic, input);

                  if(corrupt_server_data)
                     {
                     input = Test::mutate_vec(input, true);
                     size_t needed = server->received_data(input.data(), input.size());

                     size_t total_consumed = needed;

                     while(needed > 0 &&
                           result.test_lt("Never requesting more than max protocol len", needed, 18*1024) &&
                           result.test_lt("Total requested is readonable", total_consumed, 128*1024))
                        {
                        input.resize(needed);
                        rng.randomize(input.data(), input.size());
                        needed = server->received_data(input.data(), input.size());
                        total_consumed += needed;
                        }
                     }
                  else
                     {
                     size_t needed = server->received_data(input.data(), input.size());
                     result.test_eq("full packet received", needed, 0);
                     }

                  continue;
                  }

               if(s2c_traffic.size() > 0)
                  {
                  std::vector<byte> input;
                  std::swap(s2c_traffic, input);

                  if(corrupt_client_data)
                     {
                     input = Test::mutate_vec(input, true);
                     size_t needed = client->received_data(input.data(), input.size());

                     size_t total_consumed = 0;

                     while(needed > 0 && result.test_lt("Never requesting more than max protocol len", needed, 18*1024))
                        {
                        input.resize(needed);
                        rng.randomize(input.data(), input.size());
                        needed = client->received_data(input.data(), input.size());
                        total_consumed += needed;
                        }
                     }
                  else
                     {
                     size_t needed = client->received_data(input.data(), input.size());
                     result.test_eq("full packet received", needed, 0);
                     }

                  continue;
                  }

               if(client_recv.size())
                  {
                  result.test_eq("client recv", client_recv, server_sent);
                  }

               if(server_recv.size())
                  {
                  result.test_eq("server->recv", server_recv, client_sent);
                  }

               if(r > 2)
                  {
                  if(client_recv.size() && server_recv.size())
                     {
                     result.test_failure("Negotiated in the face of data corruption " + std::to_string(r));
                     }
                  }

               if(client->is_closed() && server->is_closed())
                  break;

               if(server_recv.size() && client_recv.size())
                  {
                  Botan::SymmetricKey client_key = client->key_material_export("label", "context", 32);
                  Botan::SymmetricKey server_key = server->key_material_export("label", "context", 32);

                  result.test_eq("TLS key material export", client_key.bits_of(), server_key.bits_of());

                  if(r % 2 == 0)
                     client->close();
                  else
                     server->close();
                  }
               }
            }
         }
      catch(std::exception& e)
         {
         if(r > 2)
            {
            result.test_note("Corruption caused exception");
            }
         else
            {
            result.test_failure("TLS client", e.what());
            }
         }
      }

   result.end_timer();

   return result;
   }

Test::Result test_tls_handshake(Botan::TLS::Protocol_Version offer_version,
                                Botan::Credentials_Manager& creds,
                                const Botan::TLS::Policy& policy,
                                Botan::RandomNumberGenerator& rng)
   {
   return test_tls_handshake(offer_version, creds, policy, policy, rng);
   }

Test::Result test_dtls_handshake(Botan::TLS::Protocol_Version offer_version,
                                 Botan::Credentials_Manager& creds,
                                 const Botan::TLS::Policy& client_policy,
                                 const Botan::TLS::Policy& server_policy,
                                 Botan::RandomNumberGenerator& rng)
   {
   BOTAN_ASSERT(offer_version.is_datagram_protocol(), "Test is for datagram version");

   Botan::TLS::Session_Manager_In_Memory server_sessions(rng);
   Botan::TLS::Session_Manager_In_Memory client_sessions(rng);

   Test::Result result(offer_version.to_string());

   result.start_timer();

   for(size_t r = 1; r <= 2; ++r)
      {
      bool handshake_done = false;

      auto handshake_complete = [&](const Botan::TLS::Session& session) -> bool {
         handshake_done = true;

         if(session.version() != offer_version)
            {
            result.test_failure("Offered " + offer_version.to_string() +
                                " got " + session.version().to_string());
            }

         return true;
      };

      auto next_protocol_chooser = [&](std::vector<std::string> protos) {
         if(r <= 2)
            {
            result.test_eq("protocol count", protos.size(), 2);
            result.test_eq("protocol[0]", protos[0], "test/1");
            result.test_eq("protocol[1]", protos[1], "test/2");
            }
         return "test/3";
      };

      const std::vector<std::string> protocols_offered = { "test/1", "test/2" };

      try
         {
         std::vector<byte> c2s_traffic, s2c_traffic, client_recv, server_recv, client_sent, server_sent;

         std::unique_ptr<Botan::TLS::Callbacks> server_cb(new Botan::TLS::Compat_Callbacks(
                 queue_inserter(s2c_traffic),
                 queue_inserter(server_recv),
                 std::function<void (Botan::TLS::Alert)>(print_alert),
                 handshake_complete,
                 nullptr,
                 next_protocol_chooser));

         std::unique_ptr<Botan::TLS::Callbacks> client_cb(new Botan::TLS::Compat_Callbacks(
                 queue_inserter(c2s_traffic),
                 queue_inserter(client_recv),
                 std::function<void (Botan::TLS::Alert)>(print_alert),
                 handshake_complete));

         // TLS::Server object constructed by new constructor using virtual callback interface.
         std::unique_ptr<Botan::TLS::Server> server(
            new Botan::TLS::Server(*server_cb,
                                   server_sessions,
                                   creds,
                                   server_policy,
                                   rng,
                                   true));

         // TLS::Client object constructed by new constructor using virtual callback interface.
         std::unique_ptr<Botan::TLS::Client> client(
            new Botan::TLS::Client(*client_cb,
                                   client_sessions,
                                   creds,
                                   client_policy,
                                   rng,
                                   Botan::TLS::Server_Information("server.example.com"),
                                   offer_version,
                                   protocols_offered));

         size_t rounds = 0;

         // Test DTLS using both new and legacy constructors.
         for(size_t ctor_sel = 0; ctor_sel < 2; ctor_sel++)
            {
            if(ctor_sel == 1)
               {
               c2s_traffic.clear();
               s2c_traffic.clear();
               server_recv.clear();
               client_recv.clear();
               client_sent.clear();
               server_sent.clear();
               // TLS::Server object constructed by legacy constructor.
               server.reset(
                  new Botan::TLS::Server(queue_inserter(s2c_traffic),
                                         queue_inserter(server_recv),
                                         alert_cb_with_data, 
                                         handshake_complete,
                                         server_sessions,
                                         creds,
                                         server_policy,
                                         rng,
                                         next_protocol_chooser,
                                         true));

               // TLS::Client object constructed by legacy constructor.
               client.reset(
                  new Botan::TLS::Client(queue_inserter(c2s_traffic),
                                         queue_inserter(client_recv),
                                         alert_cb_with_data, 
                                         handshake_complete,
                                         client_sessions,
                                         creds,
                                         client_policy,
                                         rng,
                                         Botan::TLS::Server_Information("server.example.com"),
                                         offer_version,
                                         protocols_offered));
               }

            while(true)
               {
               // TODO: client and server should be in different threads
               std::this_thread::sleep_for(std::chrono::microseconds(rng.next_byte() % 128));
               ++rounds;

               if(rounds > 100)
                  {
                  result.test_failure("Still here after many rounds");
                  break;
                  }

               if(handshake_done && (client->is_closed() || server->is_closed()))
                  break;

               if(client->is_active() && client_sent.empty())
                  {
                  // Choose a len between 1 and 511, todo use random chunks
                  const size_t c_len = 1 + rng.next_byte() + rng.next_byte();
                  client_sent = unlock(rng.random_vec(c_len));
                  client->send(client_sent);
                  }

               if(server->is_active() && server_sent.empty())
                  {
                  result.test_eq("server ALPN", server->next_protocol(), "test/3");

                  const size_t s_len = 1 + rng.next_byte() + rng.next_byte();
                  server_sent = unlock(rng.random_vec(s_len));
                  server->send(server_sent);
                  }

               const bool corrupt_client_data = (r == 3 && rng.next_byte() % 3 <= 1 && rounds < 10);
               const bool corrupt_server_data = (r == 4 && rng.next_byte() % 3 <= 1 && rounds < 10);

               if(c2s_traffic.size() > 0)
                  {
                  /*
                  * Use this as a temp value to hold the queues as otherwise they
                  * might end up appending more in response to messages during the
                  * handshake.
                  */
                  std::vector<byte> input;
                  std::swap(c2s_traffic, input);

                  if(corrupt_server_data)
                     {
                     try
                        {
                        input = Test::mutate_vec(input, true);
                        size_t needed = server->received_data(input.data(), input.size());

                        if(needed > 0 && result.test_lt("Never requesting more than max protocol len", needed, 18*1024))
                           {
                           input.resize(needed);
                           rng.randomize(input.data(), input.size());
                           client->received_data(input.data(), input.size());
                           }
                        }
                     catch(std::exception&)
                        {
                        result.test_note("corruption caused server exception");
                        }
                     }
                  else
                     {
                     try
                        {
                        size_t needed = server->received_data(input.data(), input.size());
                        result.test_eq("full packet received", needed, 0);
                        }
                     catch(std::exception& e)
                        {
                        result.test_failure("server error", e.what());
                        }
                     }

                  continue;
                  }

               if(s2c_traffic.size() > 0)
                  {
                  std::vector<byte> input;
                  std::swap(s2c_traffic, input);

                  if(corrupt_client_data)
                     {
                     try
                        {
                        input = Test::mutate_vec(input, true);
                        size_t needed = client->received_data(input.data(), input.size());

                        if(needed > 0 && result.test_lt("Never requesting more than max protocol len", needed, 18*1024))
                           {
                           input.resize(needed);
                           rng.randomize(input.data(), input.size());
                           client->received_data(input.data(), input.size());
                           }
                        }
                     catch(std::exception&)
                        {
                        result.test_note("corruption caused client exception");
                        }
                     }
                  else
                     {
                     try
                        {
                        size_t needed = client->received_data(input.data(), input.size());
                        result.test_eq("full packet received", needed, 0);
                        }
                     catch(std::exception& e)
                        {
                        result.test_failure("client error", e.what());
                        }
                     }

                  continue;
                  }

               // If we corrupted a DTLS application message, resend it:
               if(client->is_active() && corrupt_client_data && server_recv.empty())
                  client->send(client_sent);
               if(server->is_active() && corrupt_server_data && client_recv.empty())
                  server->send(server_sent);

               if(client_recv.size())
                  {
                  result.test_eq("client recv", client_recv, server_sent);
                  }

               if(server_recv.size())
                  {
                  result.test_eq("server recv", server_recv, client_sent);
                  }

               if(client->is_closed() && server->is_closed())
                  break;

               if(server_recv.size() && client_recv.size())
                  {
                  Botan::SymmetricKey client_key = client->key_material_export("label", "context", 32);
                  Botan::SymmetricKey server_key = server->key_material_export("label", "context", 32);

                  result.test_eq("key material export", client_key.bits_of(), server_key.bits_of());

                  if(r % 2 == 0)
                     client->close();
                  else
                     server->close();
                  }
               }
            }
         }
      catch(std::exception& e)
         {
         if(r > 2)
            {
            result.test_note("Corruption caused failure");
            }
         else
            {
            result.test_failure("DTLS handshake", e.what());
            }
         }
      }

   result.end_timer();
   return result;
   }

Test::Result test_dtls_handshake(Botan::TLS::Protocol_Version offer_version,
                                 Botan::Credentials_Manager& creds,
                                 const Botan::TLS::Policy& policy,
                                 Botan::RandomNumberGenerator& rng)
   {
   return test_dtls_handshake(offer_version, creds, policy, policy, rng);
   }

class Test_Policy : public Botan::TLS::Text_Policy
   {
   public:
      Test_Policy() : Text_Policy("") {}
      bool acceptable_protocol_version(Botan::TLS::Protocol_Version) const override { return true; }
      bool send_fallback_scsv(Botan::TLS::Protocol_Version) const override { return false; }

      size_t dtls_initial_timeout() const override { return 1; }
      size_t dtls_maximum_timeout() const override { return 8; }

      size_t minimum_rsa_bits() const override { return 1024; }
   };



class TLS_Unit_Tests : public Test
   {
   private:
      void test_with_policy(std::vector<Test::Result>& results,
                            const std::vector<Botan::TLS::Protocol_Version>& versions,
                            Botan::Credentials_Manager& creds,
                            const Botan::TLS::Policy& policy)
         {
         Botan::RandomNumberGenerator& rng = Test::rng();

         for(auto&& version : versions)
            {
            if(version.is_datagram_protocol())
               results.push_back(test_dtls_handshake(version, creds, policy, rng));
            else
               results.push_back(test_tls_handshake(version, creds, policy, rng));
            }
         }

      void test_all_versions(std::vector<Test::Result>& results,
                             Botan::Credentials_Manager& creds,
                             const std::string& kex_policy,
                             const std::string& cipher_policy,
                             const std::string& mac_policy,
                             const std::string& etm_policy)
         {
         Test_Policy policy;
         policy.set("ciphers", cipher_policy);
         policy.set("macs", mac_policy);
         policy.set("key_exchange_methods", kex_policy);
         policy.set("negotiate_encrypt_then_mac", etm_policy);

         std::vector<Botan::TLS::Protocol_Version> versions = {
            Botan::TLS::Protocol_Version::TLS_V10,
            Botan::TLS::Protocol_Version::TLS_V11,
            Botan::TLS::Protocol_Version::TLS_V12,
            Botan::TLS::Protocol_Version::DTLS_V10,
            Botan::TLS::Protocol_Version::DTLS_V12
         };

         return test_with_policy(results, versions, creds, policy);
         }

      void test_modern_versions(std::vector<Test::Result>& results,
                                Botan::Credentials_Manager& creds,
                                const std::string& kex_policy,
                                const std::string& cipher_policy,
                                const std::string& mac_policy = "AEAD",
                                const std::map<std::string, std::string>& extra_policies = {})
         {
         Test_Policy policy;
         policy.set("ciphers", cipher_policy);
         policy.set("macs", mac_policy);
         policy.set("key_exchange_methods", kex_policy);

         for(auto&& kv : extra_policies)
            policy.set(kv.first, kv.second);

         std::vector<Botan::TLS::Protocol_Version> versions = {
            Botan::TLS::Protocol_Version::TLS_V12,
            Botan::TLS::Protocol_Version::DTLS_V12
         };

         return test_with_policy(results, versions, creds, policy);
         }

   public:
      std::vector<Test::Result> run() override
         {
         Botan::RandomNumberGenerator& rng = Test::rng();

         std::unique_ptr<Botan::Credentials_Manager> creds(create_creds(rng));
         std::vector<Test::Result> results;

#if defined(BOTAN_HAS_TLS_CBC)
         for(std::string etm_setting : { "true", "false" })
            {
            test_all_versions(results, *creds, "RSA", "AES-128", "SHA-256 SHA-1", etm_setting);
            test_all_versions(results, *creds, "ECDH", "AES-128", "SHA-256 SHA-1", etm_setting);

            test_all_versions(results, *creds, "RSA", "AES-256", "SHA-1", etm_setting);
            test_all_versions(results, *creds, "ECDH", "AES-256", "SHA-1", etm_setting);

#if defined(BOTAN_HAS_CAMELLIA)
            test_all_versions(results, *creds, "RSA", "Camellia-128", "SHA-256", etm_setting);
            test_all_versions(results, *creds, "ECDH", "Camellia-256", "SHA-256 SHA-384", etm_setting);
#endif

#if defined(BOTAN_HAS_DES)
            test_all_versions(results, *creds, "RSA", "3DES", "SHA-1", etm_setting);
            test_all_versions(results, *creds, "ECDH", "3DES", "SHA-1", etm_setting);
#endif

#if defined(BOTAN_HAS_SEED)
            test_all_versions(results, *creds, "RSA", "SEED", "SHA-1", etm_setting);
#endif
            }

         test_modern_versions(results, *creds, "DH", "AES-128", "SHA-256");
#endif

         test_modern_versions(results, *creds, "RSA", "AES-128/GCM");
         test_modern_versions(results, *creds, "ECDH", "AES-128/GCM");
         test_modern_versions(results, *creds, "ECDH", "AES-128/GCM", "AEAD",
                              { { "use_ecc_point_compression", "true" } });

         std::unique_ptr<Botan::Credentials_Manager> creds_with_client_cert(create_creds(rng, true));
         test_modern_versions(results, *creds_with_client_cert, "ECDH", "AES-256/GCM");

#if defined(BOTAN_HAS_AEAD_OCB)
         test_modern_versions(results, *creds, "ECDH", "AES-128/OCB(12)");
#endif

#if defined(BOTAN_HAS_AEAD_CHACHA20_POLY1305)
         test_modern_versions(results, *creds, "ECDH", "ChaCha20Poly1305");
#endif

         test_modern_versions(results, *creds, "PSK", "AES-128/GCM");

#if defined(BOTAN_HAS_CCM)
         test_modern_versions(results, *creds, "PSK", "AES-128/CCM");
         test_modern_versions(results, *creds, "PSK", "AES-128/CCM(8)");
#endif

#if defined(BOTAN_HAS_TLS_CBC)
         // For whatever reason no (EC)DHE_PSK GCM ciphersuites are defined
         test_modern_versions(results, *creds, "ECDHE_PSK", "AES-128", "SHA-256");
         test_modern_versions(results, *creds, "DHE_PSK", "AES-128", "SHA-1");
#endif

         return results;
         }

   };

BOTAN_REGISTER_TEST("tls", TLS_Unit_Tests);

#endif

}

}
