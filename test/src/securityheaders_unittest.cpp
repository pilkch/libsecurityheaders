#include <gtest/gtest.h>

#include "security_headers.h"

TEST(SecurityHeaders, TestSecurityHeaders)
{
  security_headers::policy p;
  p.strict_transport_security_max_age_days = 365;
  const auto&& headers = security_headers::GetSecurityHeaders(p);

  EXPECT_STREQ(headers[0].name.c_str(), "Strict-Transport-Security");
  EXPECT_STREQ(headers[0].value.c_str(), "max-age=31536000; includeSubDomains; preload");
  EXPECT_STREQ(headers[1].name.c_str(), "Content-Security-Policy");
  EXPECT_STREQ(headers[1].value.c_str(), "frame-ancestors 'none'");
  EXPECT_STREQ(headers[2].name.c_str(), "X-Content-Type-Options");
  EXPECT_STREQ(headers[2].value.c_str(), "nosniff");
  EXPECT_STREQ(headers[3].name.c_str(), "X-Permitted-Cross-Domain-Policies");
  EXPECT_STREQ(headers[3].value.c_str(), "none");
  EXPECT_STREQ(headers[4].name.c_str(), "Referrer-Policy");
  EXPECT_STREQ(headers[4].value.c_str(), "no-referrer");
  EXPECT_STREQ(headers[5].name.c_str(), "Permissions-Policy");
  EXPECT_STREQ(headers[5].value.c_str(), "accelerometer=(),autoplay=(),camera=(),cross-origin-isolated=(),display-capture=(),encrypted-media=(),fullscreen=(),geolocation=(),gyroscope=(),keyboard-map=(),magnetometer=(),microphone=(),midi=(),payment=(),picture-in-picture=(),publickey-credentials-get=(),screen-wake-lock=(),sync-xhr=(self),usb=(),web-share=(),xr-spatial-tracking=(),clipboard-read=(),clipboard-write=(),gamepad=(),hid=(),idle-detection=(),interest-cohort=(),serial=(),unload=()");
  EXPECT_STREQ(headers[6].name.c_str(), "Cross-Origin-Embedder-Policy");
  EXPECT_STREQ(headers[6].value.c_str(), "require-corp; report-to=\"default\"");
  EXPECT_STREQ(headers[7].name.c_str(), "Cross-Origin-Opener-Policy");
  EXPECT_STREQ(headers[7].value.c_str(), "same-origin; report-to=\"default\"");
  EXPECT_STREQ(headers[8].name.c_str(), "Cross-Origin-Resource-Policy");
  EXPECT_STREQ(headers[8].value.c_str(), "same-origin");
  EXPECT_STREQ(headers[9].name.c_str(), "Cache-Control");
  EXPECT_STREQ(headers[9].value.c_str(), "must-revalidate, max-age=600");
}

TEST(SecurityHeaders, TestMaxAge)
{
  security_headers::policy p;

  {
    p.strict_transport_security_max_age_days = 0;
    const auto&& headers = security_headers::GetSecurityHeaders(p);

    EXPECT_STREQ(headers[0].name.c_str(), "Strict-Transport-Security");
    EXPECT_STREQ(headers[0].value.c_str(), "max-age=0; includeSubDomains; preload");
  }

  {
    p.strict_transport_security_max_age_days = 365;
    const auto&& headers = security_headers::GetSecurityHeaders(p);

    EXPECT_STREQ(headers[0].name.c_str(), "Strict-Transport-Security");
    EXPECT_STREQ(headers[0].value.c_str(), "max-age=31536000; includeSubDomains; preload");
  }

  {
    p.strict_transport_security_max_age_days = 10 * 365;
    const auto&& headers = security_headers::GetSecurityHeaders(p);

    EXPECT_STREQ(headers[0].name.c_str(), "Strict-Transport-Security");
    EXPECT_STREQ(headers[0].value.c_str(), "max-age=315360000; includeSubDomains; preload");
  }
}
