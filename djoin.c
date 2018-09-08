
#include <stdint.h>
#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <iconv.h>
#include <stdlib.h>
#include <endian.h>
#include <string.h>
#include <uuid/uuid.h>

#include "djoin.h"

#include "log.h"

#define BUF_SIZE 16384

struct djoin_info *djoin_read_domain_file(const char *filename)
{
	char wc_buf[BUF_SIZE] = {'\0'};
	char base64_buf[BUF_SIZE] = {'\0'};
	char *icon_in = wc_buf;
	char *icon_out = base64_buf;

	size_t wc_buf_size = BUF_SIZE, base64_buf_size = BUF_SIZE;

	char buf[BUF_SIZE];
	int buf_len = BUF_SIZE;

	struct djoin_info *domain_info;

	iconv_t icon_handle;

	BIO *file = BIO_new_file(filename, "r");
	if (!file)
	{
		verbose(LOG_AUTHN, L_ALERT, "Could not open file %s", filename);
		return NULL;
	}
	buf_len = BIO_read(file, wc_buf, wc_buf_size);
	BIO_free_all(file);
	if (buf_len <= 0)
	{
		verbose(LOG_AUTHN, L_ALERT, "Error reading / decoding base64 data in %s", filename);
		return NULL;
	}
	wc_buf_size = buf_len;
	if ((icon_handle = iconv_open("UTF-8", "UTF-16LE")) < 0)
	{
		verbose(LOG_AUTHN, L_ALERT, "Error creating iconv conversion handle");
		return NULL;
	}
	iconv(icon_handle, &icon_in, &wc_buf_size, &icon_out, &base64_buf_size);
	iconv_close(icon_handle);

	BIO *mbuf_bio = BIO_new_mem_buf(base64_buf + 3, BUF_SIZE - base64_buf_size - 3);

	BIO *base64 = BIO_new(BIO_f_base64());

	mbuf_bio = BIO_push(base64, mbuf_bio);

	BIO_set_flags(mbuf_bio, BIO_FLAGS_BASE64_NO_NL);

	buf_len = BIO_read(mbuf_bio, buf, BUF_SIZE);

	BIO_free_all(mbuf_bio);

	domain_info = djoin_get_domain_info(buf, buf_len);

	return domain_info;
}

void djoin_print_domain_info(struct djoin_info *info, int level)
{
	char guid_str[40];
	char sid_str[64];

	verbose(LOG_AUTHN, level, "Domain Info Version: %d (0x%lx)", info->file_header.version & 0x00000000000000FFL, info->file_header.version);
	verbose(LOG_AUTHN, level, "Size: %d bytes", info->file_header.payload_len);
	verbose(LOG_AUTHN, level, "");

	verbose(LOG_AUTHN, level, "Machine Information:");
	verbose(LOG_AUTHN, level, "	Domain: %s", info->domain_name);
	verbose(LOG_AUTHN, level, "	Computer Name: %s", info->machine_name);
	verbose(LOG_AUTHN, level, "	Computer Password: %s", info->machine_password);

	verbose(LOG_AUTHN, level, "");

	uuid_unparse(info->policy.guid, guid_str);

	djoin_unparse_sid(&info->policy.sid, sid_str);

	verbose(LOG_AUTHN, level, "Domain Policy Information:");
	verbose(LOG_AUTHN, level, "	Domain Name: %s", info->policy.netbios_domain_name);
	verbose(LOG_AUTHN, level, "	DNS Name: %s", info->policy.dns_domain_name);
	verbose(LOG_AUTHN, level, "	Forest Name: %s", info->policy.dns_forest_name);
	verbose(LOG_AUTHN, level, "	Domain GUID: %s", guid_str);
	verbose(LOG_AUTHN, level, "	SID: %s", sid_str);

	verbose(LOG_AUTHN, level, "");

	uuid_unparse(info->controller.guid, guid_str);

	verbose(LOG_AUTHN, level, "Domain Controller Information:");
	verbose(LOG_AUTHN, level, "	Domain Controller Name: %s", info->controller.domain_controller_name);
	verbose(LOG_AUTHN, level, "	Domain Controller Address: %s", info->controller.domain_controller_address);
	verbose(LOG_AUTHN, level, "	Domain Controller Address Type: 0x%x", info->controller.domain_controller_address_type);
	verbose(LOG_AUTHN, level, "	Domain GUID: %s", guid_str);
	verbose(LOG_AUTHN, level, "	Domain DNS Name: %s", info->controller.dns_domain_name);
	verbose(LOG_AUTHN, level, "	Domain Forest Name: %s", info->controller.dns_forest_name);
	verbose(LOG_AUTHN, level, "	Flags: 0x%x", info->controller.flags);
	verbose(LOG_AUTHN, level, "	Domain Site Name: %s", info->controller.dc_site_name);
	verbose(LOG_AUTHN, level, "	Computer Site Name: %s", info->controller.client_site_name);

	verbose(LOG_AUTHN, level, "");

	verbose(LOG_AUTHN, level, "Options: 0x%x", info->options);
}

void djoin_unparse_sid(struct djoin_sid *sid, char *str)
{
	sprintf(str, "S-%d-%d", sid->header, sid->size);
	char tmp[16];
	int i;

	for (i = 0; i < sid->size - 1; i++)
	{
		sprintf(tmp, "-%d", sid->data[i]);
		strcat(str, tmp);
	}
}

struct djoin_info * djoin_get_domain_info(const char *buf, int buf_len)
{
	struct djoin_info *domain_info = (struct djoin_info *)malloc(sizeof(struct djoin_info));
	struct djoin_str *str;

	uuid_t *guid;
	char *tmp;
	struct djoin_sid *sid;

	int i;

	memset(domain_info, '\0', sizeof(struct djoin_info));

	// Lets do the global info

	domain_info->file_header.version = le64toh(((struct djoin_section_header *)buf)->version);
	domain_info->file_header.payload_len = le64toh(((struct djoin_section_header *)buf)->payload_len);

	if (domain_info->file_header.version != 0xcccccccc00081001L || domain_info->file_header.payload_len != buf_len - 16)
	{
		goto invalid;
		return NULL;
	}

	if (OPTIONS_OFFSET + sizeof(uint32_t) > buf_len)
	{
		goto invalid;
	}

	domain_info->options = le32toh(*((uint32_t *)(buf + OPTIONS_OFFSET)));

	if (GLOBAL_DOMAIN_OFFSET + sizeof(struct djoin_str) > buf_len)
	{
		goto invalid;
	}

	str = (struct djoin_str *)(buf + GLOBAL_DOMAIN_OFFSET);
	if (!(domain_info->domain_name = djoin_convert_string(str, buf, buf_len)))
	{
		goto invalid;
	}

	str = (struct djoin_str *)djoin_advance_string(str);
	if (!(domain_info->machine_name = djoin_convert_string(str, buf, buf_len)))
	{
		goto invalid;
	}

	str = (struct djoin_str *)djoin_advance_string(str);
	if (!(domain_info->machine_password = djoin_convert_string(str, buf, buf_len)))
	{
		goto invalid;
	}

	// Now lets do the domain policy info

	str = (struct djoin_str *)djoin_advance_string(str);
	if (!(domain_info->policy.netbios_domain_name = djoin_convert_string(str, buf, buf_len)))
	{
		goto invalid;
	}

	str = (struct djoin_str *)djoin_advance_string(str);
	if (!(domain_info->policy.dns_domain_name = djoin_convert_string(str, buf, buf_len)))
	{
		goto invalid;
	}

	str = (struct djoin_str *)djoin_advance_string(str);
	if (!(domain_info->policy.dns_forest_name = djoin_convert_string(str, buf, buf_len)))
	{
		goto invalid;
	}

	if (DNS_POLICY_GUID_OFFSET + sizeof(uuid_t) > buf_len)
	{
		goto invalid;
	}

	guid = (uuid_t*)(buf + DNS_POLICY_GUID_OFFSET);
	memcpy(domain_info->policy.guid, guid, sizeof(uuid_t));

	// Now the SID...
	// There are 4 bytes after the GUID - not sure what they are, so we skip them.
	tmp = (char *)(djoin_advance_string(str) + 4);
	sid = (struct djoin_sid *)tmp;

	if (tmp > buf + buf_len || (char *)&sid->data[0] > buf + buf_len)
	{
		goto invalid;
	}

	domain_info->policy.sid.header = sid->header & 0x000000FF;
	domain_info->policy.sid.size   = be32toh(sid->size);

	if (domain_info->policy.sid.size > MAX_SID_ELEMENTS)
	{
		verbose(LOG_AUTHN, L_ALERT, "Error decoding data - too many SID elements (%d - max is %d)", domain_info->policy.sid.size, MAX_SID_ELEMENTS);
		goto invalid;
	}

	for (i = 0; i < domain_info->policy.sid.size - 1; i++)
	{
		if ((char *)&sid->data[i] > buf + buf_len)
		{
			goto invalid;
		}
		domain_info->policy.sid.data[i] = sid->data[i];
	}

	// Now we do the domain controller information
	tmp += sizeof(uint32_t) * (domain_info->policy.sid.size + 1);
	str = (struct djoin_str *)tmp;
	if (!(domain_info->controller.domain_controller_name = djoin_convert_string(str, buf, buf_len)))
	{
		goto invalid;
	}

	str = (struct djoin_str *)djoin_advance_string(str);
	if (!(domain_info->controller.domain_controller_address = djoin_convert_string(str, buf, buf_len)))
	{
		goto invalid;
	}

	if (DOMAIN_CONTROLLER_ADDR_TYPE_OFFSET + sizeof(uint32_t) > buf_len)
	{
		goto invalid;
	}

	domain_info->controller.domain_controller_address_type = le32toh(*((uint32_t *)(buf + DOMAIN_CONTROLLER_ADDR_TYPE_OFFSET)));

	if (DOMAIN_CONTROLLER_GUID_OFFSET + sizeof(uuid_t) > buf_len)
	{
		goto invalid;
	}

	guid = (uuid_t*)(buf + DOMAIN_CONTROLLER_GUID_OFFSET);
	memcpy(domain_info->controller.guid, guid, sizeof(uuid_t));

	str = (struct djoin_str *)djoin_advance_string(str);
	if (!(domain_info->controller.dns_domain_name = djoin_convert_string(str, buf, buf_len)))
	{
		goto invalid;
	}

	str = (struct djoin_str *)djoin_advance_string(str);
	if (!(domain_info->controller.dns_forest_name = djoin_convert_string(str, buf, buf_len)))
	{
		goto invalid;
	}

	if (DOMAIN_CONTROLLER_FLAGS_OFFSET + sizeof(uint32_t) > buf_len)
	{
		goto invalid;
	}

	domain_info->controller.flags = le32toh(*((uint32_t *)(buf + DOMAIN_CONTROLLER_FLAGS_OFFSET)));

	str = (struct djoin_str *)djoin_advance_string(str);
	if (!(domain_info->controller.dc_site_name = djoin_convert_string(str, buf, buf_len)))
	{
		goto invalid;
	}

	str = (struct djoin_str *)djoin_advance_string(str);
	if (!(domain_info->controller.client_site_name = djoin_convert_string(str, buf, buf_len)))
	{
		goto invalid;
	}

	return domain_info;

	invalid:

	verbose(LOG_AUTHN, L_ALERT, "Invalid Offline Domain Join Data");
	djoin_free_info(domain_info);
	return NULL;
}

char * djoin_convert_string(struct djoin_str *str, const char *buf, int buf_len)
{
	char *ret;
	iconv_t icon_handle;
	char *icon_in, *icon_out;
	size_t icon_in_size, icon_out_size;

	if ((&str->buffer) - 1 > buf + buf_len || &str->buffer + str->buf_len > buf + buf_len)
	{
		verbose(LOG_AUTHN, L_ALERT, "Corrupt djoin string buffer");
		return NULL;	
	}

	if (le32toh(str->buf_size) == 0)
	{
		ret = (char *)malloc(1);
		ret[0] = '\0';
		return ret;
	}

	if ((icon_handle = iconv_open("UTF-8", "UTF-16LE")) < 0)
	{
		verbose(LOG_AUTHN, L_ALERT, "Error creating iconv conversion handle");
		return NULL;
	}
	ret = (char *)malloc(le32toh(str->buf_len + 1));

	icon_in_size = le32toh(str->buf_len * 2); // 2 bytes per character
	icon_out_size = le32toh(str->buf_len);

	icon_in = &str->buffer;
	icon_out = ret;

	iconv(icon_handle, &icon_in, &icon_in_size, &icon_out, &icon_out_size);
	iconv_close(icon_handle);

	ret[le32toh(str->buf_len)] = '\0'; // NULL terminate just in case.

	return ret;
}

char *djoin_advance_string(struct djoin_str *str)
{
	if (le32toh(str->buf_len) % 2)
	{
		return (((char *)str) + 12 + ((le32toh(str->buf_len) + 1) * 2));
	}
	return (((char *)str) + 12 + (le32toh(str->buf_len) * 2));
}


#define djoin_free_if_not_null(V) if (V) { free(V); }

void djoin_free_info(struct djoin_info *i)
{
	djoin_free_if_not_null(i->domain_name);
	djoin_free_if_not_null(i->machine_name);
	djoin_free_if_not_null(i->machine_password);

	djoin_free_if_not_null(i->policy.netbios_domain_name);
	djoin_free_if_not_null(i->policy.dns_domain_name);
	djoin_free_if_not_null(i->policy.dns_forest_name);

	djoin_free_if_not_null(i->controller.domain_controller_name);
	djoin_free_if_not_null(i->controller.domain_controller_address);
	djoin_free_if_not_null(i->controller.dns_domain_name);
	djoin_free_if_not_null(i->controller.dns_forest_name);
	djoin_free_if_not_null(i->controller.dc_site_name);
	djoin_free_if_not_null(i->controller.client_site_name);

	free(i);
}
