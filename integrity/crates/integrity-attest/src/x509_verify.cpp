/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stddef.h>
#include <stdint.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

extern "C" bool yasvara_verify_x509_signature(
    const uint8_t* cert_buf, size_t cert_len,
    const uint8_t* issuer_buf, size_t issuer_len) {
  if (!cert_buf || cert_len == 0 || !issuer_buf || issuer_len == 0) {
    return false;
  }
  const uint8_t* cert_p = cert_buf;
  bssl::UniquePtr<X509> cert(d2i_X509(nullptr, &cert_p, static_cast<long>(cert_len)));
  if (!cert || cert_p != cert_buf + cert_len) {
    ERR_clear_error();
    return false;
  }
  const uint8_t* issuer_p = issuer_buf;
  bssl::UniquePtr<X509> issuer(d2i_X509(nullptr, &issuer_p, static_cast<long>(issuer_len)));
  if (!issuer || issuer_p != issuer_buf + issuer_len) {
    ERR_clear_error();
    return false;
  }
  EVP_PKEY* pubkey = X509_get0_pubkey(issuer.get());
  if (!pubkey) {
    ERR_clear_error();
    return false;
  }
  int ok = X509_verify(cert.get(), pubkey);
  ERR_clear_error();
  return ok == 1;
}
