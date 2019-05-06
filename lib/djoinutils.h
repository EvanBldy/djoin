
#ifndef _AUTHENT_DJOIN_H
#define _AUTHENT_DJOIN_H

#include <uuid/uuid.h>
#include <stdint.h>

/* Decode the file format produced by off-line domain join files (produced by djoin.exe)
 */

#ifdef __cplusplus
using namespace std;
extern "C" {
#endif

#define OPTIONS_OFFSET 64 /* 0x40 */
#define DNS_POLICY_GUID_OFFSET 108 /* 0x6c */
#define DOMAIN_CONTROLLER_GUID_OFFSET (DNS_POLICY_GUID_OFFSET + 32 /* 0x20 */)
#define DOMAIN_CONTROLLER_ADDR_TYPE_OFFSET 136 /* 0x88 */
#define DOMAIN_CONTROLLER_FLAGS_OFFSET 164 /* 0xa4 */

// start of the string structs
#define GLOBAL_DOMAIN_OFFSET 180 /* 0xb4 */
// then comes the machine name
// then comes the machine password

// Then comes the DomainDNSPolicy:
// NetBIOS Domain String
// DNS Domain String
// DNS Forest String
//   -- Domain GUID is defined by the offset: DNS_POLICY_GUID_OFFSET
//
// Then comes the SID - skip 4 bytes, and then: S-1-5-21-782951354-3473015906-526000759
// uint8_t                      - S1
// uint8_t                      - ??? Skip. Seems to be 0x4 but I dont know what this means
// Big Endian, 6 bytes (32 bit) - the number of section (including this one) to follow - normally 5 (0x5)
// Little Endian                - 32-bits                          - normally 21 (0x15)
// Little Endian                - 32-bits
// .... until the number of sections has been consumed
//
// Then comes the DC Info - back to string encoding again...
// DomainControllerName,
// DomainControllerAddress,
//   -- address-type - comes from DOMAIN_CONTROLLER_ADDR_TYPE_OFFSET (32-bit value)
//   -- domain GUI - from DOMAIN_CONTROLLER_GUID_OFFSET
// DomainName,
// DnsForestName
//   -- flags - comes from DOMAIN_CONTROLLER_FLAGS_OFFSET

#define MAX_SID_ELEMENTS 10

struct djoin_sid
{
	uint32_t header;
	uint32_t size;
	uint32_t data[MAX_SID_ELEMENTS];
} __attribute__((packed));

struct djoin_str
{
	uint32_t buf_size;     // How wide the buffer is - number of 16-bit (UTF-16-LE) characters
	uint32_t buf_offset;   // The start of information within the buffera (characters, not bytes!)
	uint32_t buf_len;      // How many characters to use, starting from buf_offset
	char     buffer;
} __attribute__((packed));

#define DJOIN_ADDRESS_TYPE_IPV4 0x01
#define DJOIN_ADDRESS_TYPE_NETBIOS_NAME 0x02

#define DJOIN_FLAG_FOREST_NAME_DNS    0x00000001
#define DJOIN_FLAG_DOMAIN_NAME_DNS    0x00000002
#define DJOIN_FLAG_DC_NAME_DNS        0x00000004
#define DJOIN_FLAG_LEVEL_2012         0x00010000
#define DJOIN_FLAG_AD_WEB_SERVICE     0x00040000
#define DJOIN_FLAG_WRITABLE_DC        0x00080000
#define DJOIN_FLAG_READONLY_DC        0x00100000
#define DJOIN_FLAG_DIR_NC_SERVICE     0x00200000
#define DJOIN_FLAG_NTP_HW_AVAILABLE   0x00400000
#define DJOIN_FLAG_WRITABLE_LDAP      0x00800000
#define DJOIN_FLAG_CLOSEST_TO_CLIENT  0x01000000
#define DJOIN_FLAG_NTP_ONLY_AVAILABLE 0x02000000
#define DJOIN_FLAG_KRB_KDC_AVAILABLE  0x04000000
#define DJOIN_FLAG_DIR_SERVICE        0x08000000
#define DJOIN_FLAG_LDAP_SERVICE       0x10000000
#define DJOIN_FLAG_GLOBAL_CATALOGUE   0x20000000
#define DJOIN_FLAG_PRIMARY_DC         0x80000000

struct djoin_domain_controller
{
	char *domain_controller_name;
	char *domain_controller_address;
	uint32_t domain_controller_address_type;
	uuid_t guid;
	char *dns_domain_name;
	char *dns_forest_name;
	uint32_t flags;
	char *dc_site_name;
	char *client_site_name;
};

struct djoin_domain_dns_policy
{
	char *netbios_domain_name;
	char *dns_domain_name;
	char *dns_forest_name;
	uuid_t guid;
	struct djoin_sid sid;
};

struct djoin_section_header
{
	uint64_t version;
	uint64_t payload_len;
} __attribute__((packed));

struct djoin_info
{
	struct djoin_section_header file_header;

	char *domain_name;
	char *machine_name;
	char *machine_password;

	struct djoin_domain_dns_policy policy;

	struct djoin_domain_controller controller;

	uint32_t options;
};

// Parse the domain info from the specified file
struct djoin_info *djoin_read_domain_file(const char *file);

// Parse the domain info data
struct djoin_info *djoin_get_domain_info(const char *buf, int buf_len);

// Print out the domain information
void djoin_print_domain_info(struct djoin_info *info);

// Get the string represented by the string buffer, making sure it does not go out
// of bounds of the underlying buffer
char * djoin_convert_string(struct djoin_str *str, const char *buf, int buf_len);

// Get the next field after the specified string
char *djoin_advance_string(struct djoin_str *str);

// Convert a SID to a string. str should be at least 64 bytes
void djoin_unparse_sid(struct djoin_sid *sid, char *str);

// Free a domain-info structure
void djoin_free_info(struct djoin_info *i);

#ifdef __cplusplus
}
#endif

#endif /* _AUTHENT_DJOIN_H */