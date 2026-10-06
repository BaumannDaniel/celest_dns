# Project Structure

The project is split into a dns parser found under /lib and a small command line tool, found under /cli,
demonstrating the usage of the parser

# Build

Requirements: a C compiler (e.g. gcc), CMake (>= 3.28) and Ninja.

The tests use [Unity](https://github.com/ThrowTheSwitch/Unity), which is included as a git submodule.
Fetch it after cloning (or clone with `--recurse-submodules`):

```
git submodule update --init --recursive
```

Configure and build the project using the `dev` preset (Debug build, output in `build-dev/`):

```
cmake --preset dev
cmake --build build-dev
```

### Run tests

```
ctest --test-dir build-dev --output-on-failure
```

# lib

The lib holds a single header file. It defines several functions, structs and enums,
needed when dealing with dns messages.

The naming of structs and enums is derived from 
[RFC1035](https://datatracker.ietf.org/doc/html/rfc1035).
For example BaseType.TYPE_A refers to the Type A defined in
[RFC1035 3.2.2](https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2).
And the struct DnsMessage refers to [RFC2035 4.1](https://datatracker.ietf.org/doc/html/rfc1035#section-4.1).

Also the TYPE_AAAA is provided by the BaseType enum, referring to IPv6 record types,
as defined in [RFC1886 2.1](https://datatracker.ietf.org/doc/html/rfc1886#section-2.1).

### parse_dns_header()

Function that can be used to only parse the header section of a dns message, from a byte array.

```c
const u_int8_t *dns_message_buffer = ...;
DnsHeader dns_header;
parse_dns_header(dns_message_buffer, &dns_header);
```

### parse_dns_message()

Function that can be used to fully parse a dns message from a byte array.
The function will return 0 if parsing the message succeeded, otherwise it will return -1;

```c
const u_int8_t *dns_message_buffer = ...;
DnsMessage dns_message;
int parseResult = parse_dns_message(dns_message_buffer, &dns_message);
...
free_dns_message(&dns_message);
```

The questions, answers, authorities, additional fields of the DnsMessage struct
will hold dynamically allocated arrays. With the individual Questions and Resource Records,
also referencing dynamically allocated memory area. Thus after usage **free_dns_message()**
should be invoked.

### dns_message_to_buffer()

Function that can be used to convert a DnsMessage struct to a byte array.
The function will return a pointer to the byte array if successful, else it returns NULL.
The function also takes a pointer **buffer_size_ptr**, which, if not NULL, will be set to the number of parsed bytes.

```c
DnsMessage dns_message = ...;
u_int16_t dns_message_buffer_size = 0;
const u_int8_t *dns_message_buffer = dns_message_to_buffer(query_dns_message, &dns_message_buffer_size);
...
free(dns_message_buffer);
```

### TODOs:


# cli

The cli provides some basic functionality to resolve domain names.

The cli will send separate queries to retrieve ipv4 and ipv6 addresses,
as [RFC9619](https://datatracker.ietf.org/doc/html/rfc9619) limits **qd_count** to 1,
for queries.

### Options

[required]\
**-d**: the domain name that shall be resolved\
**-s**: the ip of the dns server, either Ipv4 [xxx.xxx.xxx.xxx] or Ipv6 [e.g. 2001:4860:4860::8888]\

[optional]\
**-p**: The port used by the dns server [default = 53]

### Example

```
celest_cli -d facebook.com -s 76.76.2.0 -p 53
```

