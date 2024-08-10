#include <gtest/gtest.h>

#include "security_headers.h"

TEST(SecurityHeaders, TestSecurityHeaders)
{
  security_headers::policy p;
  p.strict_transport_security_max_age_days = 365;
  const auto&& headers = security_headers::GetSecurityHeaders(p);

  EXPECT_STREQ(headers[0].name.c_str(), "strict-transport-security");
  EXPECT_STREQ(headers[0].value.c_str(), "max-age=31536000; includeSubDomains; preload");
  EXPECT_STREQ(headers[1].name.c_str(), "x-content-type-options");
  EXPECT_STREQ(headers[1].value.c_str(), "nosniff");
  EXPECT_STREQ(headers[2].name.c_str(), "referrer-policy");
  EXPECT_STREQ(headers[2].value.c_str(), "same-origin");
  EXPECT_STREQ(headers[3].name.c_str(), "content-security-policy");
  EXPECT_STREQ(headers[3].value.c_str(), "frame-ancestors 'none'");
  EXPECT_STREQ(headers[4].name.c_str(), "permissions-policy");
  EXPECT_STREQ(headers[4].value.c_str(), "");
  EXPECT_STREQ(headers[5].name.c_str(), "cross-origin-embedder-policy-report-only");
  EXPECT_STREQ(headers[5].value.c_str(), "require-corp; report-to=\"default\"");
  EXPECT_STREQ(headers[6].name.c_str(), "cross-origin-opener-policy");
  EXPECT_STREQ(headers[6].value.c_str(), "same-origin; report-to=\"default\"");
  EXPECT_STREQ(headers[7].name.c_str(), "cross-origin-opener-policy-report-only");
  EXPECT_STREQ(headers[7].value.c_str(), "same-origin; report-to=\"default\"");
  EXPECT_STREQ(headers[8].name.c_str(), "cross-origin-resource-policy");
  EXPECT_STREQ(headers[8].value.c_str(), "same-origin");
}
