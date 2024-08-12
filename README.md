### libsecurityheaders

## About

Welcome to the world's smallest library. It is just one function.  
Security headers are HTTP headers that we can set to restrict bad behaviour, usually cross site requests and similar.  [Tanya Janca](https://shehackspurple.ca/) is the boss of the security headers fan club and covers them in her book [Alice and Bob Learn Application Security](https://www.amazon.com.au/Alice-Bob-Learn-Application-Security/dp/1119687357).  Inspired by that book, I added security headers to a few of my projects, and to avoid repeating myself I've created this library.  

**Warning: This library is opinionated and returns the security headers that I personally use in my projects. I try to keep them up to date as new security headers come out, mainly by following the recommendations on https://securityheaders.com/, but security headers move pretty quickly so and I could get a few months behind, beware.**  

Goals:
- Try to use as many of the recommendations from sites like https://securityheaders.com/ as possible
- This library is very opinionated and only supports the security headers that I use, it doesn't allow CORS for example, you could add CORS to the security headers that are returned, or you could submit a patch to this library that adds a flag to add it

Notes:
- It is a header only library because it is one function, there is not really anything too it. It is barely a library

## Building

### Install Prerequisites

```bash
sudo yum install gtest-devel
```

### Build the example application and unit tests

gcc

```bash
cmake .
make -j
```

Clang

```bash
rm -rf CMakeFiles CMakeCache.txt cmake_install.cmake
CC=/usr/bin/clang CXX=/usr/bin/clang++ cmake .
make -j
```

Generates securityheaders_example and securityheaders_test.

### Run the example (Just generates and prints out the security headers)

```bash
./securityheaders_example
```

### Run the unit tests

```bash
./securityheaders_test
```

## Usage

There is a simple example in example/securityheaders_example.cpp.

Include security_headers.h:
```cpp
#include "security_headers.h"
```

Print out the headers:
```cpp
security_headers::policy p;
p.strict_transport_security_max_age_days = 365;
const auto&& headers = security_headers::GetSecurityHeaders(p);

for (auto&& h : headers) {
  std::cout<<h.name<<": "<<h.value<<std::endl;
}
```

Or, add them to a libmicrohttpd HTTP response:
```cpp
void ServerAddSecurityHeaders(struct MHD_Response* response)
{
  // NOTE: The headers are very static, so you could just call this once and reuse the result for all responses
  security_headers::policy p;
  p.strict_transport_security_max_age_days = 365;
  const auto&& headers = security_headers::GetSecurityHeaders(p);

  for (auto&& h : headers) {
    MHD_add_response_header(response, h.name.c_str(), h.value.c_str());
  }
}
```
