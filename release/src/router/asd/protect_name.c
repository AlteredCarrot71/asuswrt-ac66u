#include <stdlib.h>
#include <shared.h>

const char version_name[][16] = {{'v', 'e', 'r', 's', 'i', 'o', 'n', '\0'}};
const char blockdns_name[][32] = {{'b','l','o','c','k', 'd', 'n', 's', '\0'}};
const char blockfile_name[][32] = {{'b','l','o','c','k', 'f', 'i', 'l', 'e', '\0'}};
const char blockip_name[][32] = {{'b','l','o','c','k', 'i', 'p', '\0'}};
const char chknvram_name[][32] = {{'c', 'h', 'k', 'n','v','r','a','m', '\0'}};
const char publickey_name[][32] = {{'p','u','b','l','i','c','k','e','y','\0'}};
const char cur_iptables[][32] = {{'/', 't', 'm', 'p', '/', 'c', 'u', 'r', '_', 'i', 'p', 't', 'a', 'b', 'l', 'e', 's', '\0'}};
const char default_path[][64] = {{'/','r','o','m','/','a','s','d','\0'}};
#ifdef RTCONFIG_LIVE_UPDATE_RSA
const char dl_path_file_name[][32] = {{'s','d','2','.','p','h','p', '\0'}};
#else
const char dl_path_file_name[][32] = {{'s','d','.','p','h','p', '\0'}};
#endif
const char public_key_path[][32] = {{'/','u','s','r','/','s','b','i','n','/','p','u','b','l','i','c','.','p','e','m','\0'}};
const char temp_public_key_path[][32] = {{'/','t','m','p','/','p','u','b','l','i','c','.','p','e','m','\0'}};
const char asd_json_log_path[][32] = {{'/','t','m','p','/','a','s','d','_','j','s','o','n','\0'}};
	
#if defined(RTCONFIG_JFFS2) || defined(RTCONFIG_BRCM_NAND_JFFS2) || \
    defined(RTCONFIG_YAFFS) || \
    defined(RTCONFIG_UBIFS)
const char local_ver_path[][64] = {{'/','j','f','f','s','/','a','s','d','/','v','e','r','s','i','o','n','\0'}};
const char local_ver_bk_path[][64] = {{'/','j','f','f','s','/','a','s','d','/','v','e','r','s','i','o','n','b','k','\0'}};
const char local_asd_dir[][64] = {{'/','j','f','f','s','/','a','s','d','\0'}};
const char local_folder[][16] = {{'/','j','f','f','s','\0'}};
#else
const char local_ver_path[][64] = {{'/','t','m','p','/','a','s','d','/','v','e','r','s','i','o','n','\0'}};
const char local_ver_bk_path[][64] = {{'/','t','m','p','/','a','s','d','/','v','e','r','s','i','o','n','b','k','\0'}};
const char local_asd_dir[][64] = {{'/','t','m','p','/','a','s','d','\0'}};
const char local_folder[][16] = {{'/','t','m','p','\0'}};
#endif



