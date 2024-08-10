#pragma once

#include <cstdint>

#include <string>
#include <vector>

namespace security_headers {

struct policy {
  policy() :
    strict_transport_security_max_age_days(365)
  {
  }

  uint16_t strict_transport_security_max_age_days;
};

struct header {
  std::string name;
  std::string value;
};

// NOTE: This could return an std::map, but I like the ordering and it makes debugging easier
const std::vector<header> GetSecurityHeaders(const policy& p)
{
  const uint32_t strict_transport_security_max_age_seconds = p.strict_transport_security_max_age_days * 24 * 60 * 60;

  const std::vector<header> security_headers = {
    { "strict-transport-security", "max-age=" + std::to_string(strict_transport_security_max_age_seconds) + "; includeSubDomains; preload" },
    { "x-content-type-options", "nosniff" },
    { "referrer-policy", "same-origin" },
    { "content-security-policy", "frame-ancestors 'none'" },
    { "permissions-policy", "" },
    { "cross-origin-embedder-policy-report-only", "require-corp; report-to=\"default\"" },
    { "cross-origin-opener-policy", "same-origin; report-to=\"default\"" },
    { "cross-origin-opener-policy-report-only", "same-origin; report-to=\"default\"" },
    { "cross-origin-resource-policy", "same-origin" }
  };

  return security_headers;
}

}
