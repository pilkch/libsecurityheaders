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
    // Strengthens your implementation of TLS by getting the User Agent to enforce the use of HTTPS
    { "Strict-Transport-Security", "max-age=" + std::to_string(strict_transport_security_max_age_seconds) + "; includeSubDomains; preload" },
    // Protect from XSS attacks
    { "Content-Security-Policy", "frame-ancestors 'none'" },
    // Stops a browser from trying to MIME-sniff the content type and forces it to stick with the declared content-type
    { "X-Content-Type-Options", "nosniff" },
    // Don't allow Flash and Silverlight
    { "X-Permitted-Cross-Domain-Policies", "none" },
    // Don't set the referrer
    { "Referrer-Policy", "no-referrer" },
    // Control which features and APIs can be used on this page https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy
    // Disable everything by default (This is definitely something you will want to consider, these settings are too strict for regular web sites)
    // https://github.com/OWASP/www-project-secure-headers/blob/master/tab_bestpractices.md
    { "Permissions-Policy", "accelerometer=(),autoplay=(),camera=(),cross-origin-isolated=(),display-capture=(),encrypted-media=(),fullscreen=(),geolocation=(),gyroscope=(),keyboard-map=(),magnetometer=(),microphone=(),midi=(),payment=(),picture-in-picture=(),publickey-credentials-get=(),screen-wake-lock=(),sync-xhr=(self),usb=(),web-share=(),xr-spatial-tracking=(),clipboard-read=(),clipboard-write=(),gamepad=(),hid=(),idle-detection=(),interest-cohort=(),serial=(),unload=()" },
    { "Cross-Origin-Embedder-Policy", "require-corp; report-to=\"default\"" },
    { "Cross-Origin-Opener-Policy", "same-origin; report-to=\"default\"" },
    { "Cross-Origin-Resource-Policy", "same-origin" },
    { "Cache-Control", "must-revalidate, max-age=600" },
  };

  return security_headers;
}

}
