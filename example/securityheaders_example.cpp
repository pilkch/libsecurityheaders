#include <iostream>

#include "security_headers.h"

int main(int argc, char** argv)
{
  security_headers::policy p;
  p.strict_transport_security_max_age_days = 365;
  const auto&& headers = security_headers::GetSecurityHeaders(p);

  // Print out the headers
  std::cout<<"Headers"<<std::endl;
  for (auto&& h : headers) {
    std::cout<<h.name<<": "<<h.value<<std::endl;
  }

  return EXIT_SUCCESS;
}
