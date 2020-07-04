#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h> 

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h> 
#include <openssl/bio.h>

#include <shared.h>

#include "security_daemon.h"
#include "utility.h"

#define ASD_LOG_PATH	"/tmp/asd.log"
#define ASD_BK_LOG_PATH	"/tmp/asd.log.1"
#define ASD_LOG_MAX_SIZE	1024*1024

#define ASD_SHA256_LEN 32


#if 0	// Did not use now.
/*******************************************************************
* NAME: _read_file_without_signature
* AUTHOR: Andy Chiu
* CREATE DATE: 2019/12/18
* DESCRIPTION: read file exclude the signature data in the end of the file
* INPUT:  path: string, the path of the file.
* OUTPUT:  None
* RETURN: pointer of the data content or NULL 
* NOTE: Must free the return data externally 
*******************************************************************/
static char *_read_file_without_signature(const char *path)
{
	char *buf = NULL;
	unsigned long sz = 0;
	FILE *fp;

	if(!path || access(path, F_OK) == -1)
	{
		ASD_DBG("[%s]Parameter error. Path is NULL!\n", __FUNCTION__);
		return NULL;
	}

	sz = f_size(path);

	if(sz <= ASD_SIG_LEN)
	{
		ASD_DBG("[%s]File size is smaller than sha256 signature length!\n", __FUNCTION__);
		return NULL;
	}

	fp = fopen(path, "r");
	if(fp)
	{		
		buf = calloc(sz - ASD_SIG_LEN + 1, 1);
		if(!buf)
		{
			ASD_DBG("[%s] Memory alloc fail!\n", __FUNCTION__);			
		}
		else
		{
			fread(buf, 1, sz - ASD_SIG_LEN, fp);
		}
		fclose(fp);
	}
	else
	{
		ASD_DBG("[%s]Cannot open file(%s)\n", __FUNCTION__, path);
		return NULL;
	}
	return buf;
}

/*******************************************************************
* NAME: dump_content
* AUTHOR: Andy Chiu
* CREATE DATE: 2019/12/18
* DESCRIPTION: dump the data in the data structure, CONTENT_BY_LINE.
* INPUT:  content: pointer of CONTENT_BY_LINE.
* OUTPUT:  None
* RETURN: None
* NOTE:
*******************************************************************/
void dump_content(CONTENT_BY_LINE *content)
{
	int i;
	if(content)
	{
		printf("[%s, %d]number=%d\n", __FUNCTION__, __LINE__, content->num);
		for(i = 0; i < content->num; ++i)
		{
			printf("[%s, %d]%d, %s\n", __FUNCTION__, __LINE__, i, *(content->line + i));
		}
	}
}

/*******************************************************************
* NAME: free_content
* AUTHOR: Andy Chiu
* CREATE DATE: 2019/12/18
* DESCRIPTION: free the memory of CONTENT_BY_LINE
* INPUT:  content: pointer of CONTENT_BY_LINE.
* OUTPUT: None
* RETURN: ASD_SUCCESS or ASD_FAIL 
* NOTE:
*******************************************************************/
void free_content(CONTENT_BY_LINE *content)
{
	int i;

	if(content)
	{
		for(i = 0; i < content->num; ++i)
		{
			SAFE_FREE(*(content->line + i));
		}
		SAFE_FREE(content->line)
		SAFE_FREE(content->checked);
	}
}

/*******************************************************************
* NAME: read_file_in_content
* AUTHOR: Andy Chiu
* CREATE DATE: 2019/12/18
* DESCRIPTION: read each line in file into CONTENT_BY_LINE. Can use filter to get specific line.
* INPUT: file_path: string, full path of the file.
*        filter: strnig, use to get line with the filter string. Can be NULL to skip this option. 
* OUTPUT:  content: pointer of CONTENT_BY_LINE
* RETURN: number of the line be recorded or ASD_FAIL.
* NOTE: Must call free_content to free the output value, content externally.
*******************************************************************/
int read_file_in_content(const char *file_path,  const char *filter, CONTENT_BY_LINE *content)
{
	char *p, *buf = NULL;
	int i, num;
	
	if(!file_path || !content)
		return ASD_FAIL;

	buf = _read_file_without_signature(file_path);
	if(buf)
	{
		//count line number
		num = 0;
		p = buf;
		while(p)
		{
			if(*p == '\n')
				++p;
			
			if(!filter)
				++num;
			else if(!strncmp(p, filter, strlen(filter)))
				++num;
			p = strchr(p, '\n');
		}			

		//alloc a string pointer array
		content->line = calloc(num, sizeof(char*));
		content->num = num;
		if(!content->line)
		{
			ASD_DBG("[%s]Memory alloc fail!\n", __FUNCTION__);
			SAFE_FREE(buf);
			return ASD_FAIL;
		}

		content->checked = calloc(num, 1);
		if(!content->checked)
		{
			ASD_DBG("[%s]Memory alloc fail!\n", __FUNCTION__);
			SAFE_FREE(buf);
			SAFE_FREE(content->line);
			return ASD_FAIL;
		}
		
		p = strtok(buf, "\n");
		i = 0;

		while(p)
		{
			if(!filter)
			{
				*(content->line + i) = strdup(p);
				++i;
			}
			else if(!strncmp(p, filter, strlen(filter)))
			{
				*(content->line + i) = strdup(p);
				++i;
			}
			p = strtok(NULL, "\n");
		}		
		SAFE_FREE(buf);
		return i;
	}	
	return ASD_FAIL;
}
#endif

/*******************************************************************
* NAME: _read_public_key
* AUTHOR: Andy Chiu
* CREATE DATE: 2019/12/18
* DESCRIPTION: get public key in the device
* INPUT:  None
* OUTPUT:  None
* RETURN: pointer of RSA or NULL 
* NOTE: Must free this RSA pointer externally.
*******************************************************************/
static RSA* _read_public_key()
{
	FILE *fp;
	RSA *pubRSA = NULL;

	fp = fopen(public_key_path[0], "r");
	if(fp)
	{
		if(!PEM_read_RSA_PUBKEY(fp, &pubRSA, NULL, NULL))
		{
			ASD_DBG("[%s]PEM_read_RSA_PUBKEY error\n", __FUNCTION__);
		}
		fclose(fp);
	}
	else
		ASD_DBG("[%s]Cannot open public key (%s)\n", __FUNCTION__, public_key_path[0]);

	return pubRSA;
}	

/*******************************************************************
* NAME: asdprint
* AUTHOR: Andy Chiu
* CREATE DATE: 2019/12/18
* DESCRIPTION: show debug message on the console and write it to the debug log.
* INPUT: 
* OUTPUT: None  
* RETURN: None
* NOTE:
*******************************************************************/
void asdprint(const char * format, ...)
{
	FILE *f, *f2;
	int nfd;
	va_list args;
	struct stat st;
	char buf[256];
	size_t ret;

	//dump in console
	if (((nfd = open("/dev/console", O_WRONLY | O_NONBLOCK)) > 0) &&
	    (f = fdopen(nfd, "w")))
	{
		va_start(args, format);
		vfprintf(f, format, args);
		va_end(args);
		fclose(f);
	}
	else
	{
		va_start(args, format);
		vfprintf(stderr, format, args);
		va_end(args);
	}

	if (nfd != -1) close(nfd);

	//Move the file which reached the maximum size to backup
	if(stat(ASD_LOG_PATH, &st) != -1)
	{ 
		//check file size
		if(st.st_size > ASD_LOG_MAX_SIZE)
		{
			//move file to backup
			f = fopen(ASD_LOG_PATH, "r");
			if(f)
			{
				f2 = fopen(ASD_BK_LOG_PATH, "w");
				if(f2)
				{
					while(ret = fread(buf, 1, sizeof(buf), f))
					{
						fwrite(buf, 1, ret, f2);
					}
					fclose(f2);
				}	
				fclose(f);
			}
			//delete the original log file
			unlink(ASD_LOG_PATH);
		}
	}
			
	//write the log to file
	f = fopen(ASD_LOG_PATH, "a");
	if(f)
	{
		va_start(args, format);
		vfprintf(f, format, args);
		va_end(args);
		fclose(f);
	}	
}

/*******************************************************************
* NAME: _verify_with_public_key
* AUTHOR: Andy Chiu
* CREATE DATE: 2019/12/18
* DESCRIPTION: verify data with public key
* INPUT:  buf: string, data content for verify.
*         buf_len: number, the length of buf.
*         signature: signature data
*         sig_len: the length of signature
* OUTPUT:  None
* RETURN: ASD_SUCCESS or ASD_FAIL 
* NOTE:
*******************************************************************/
static int _verify_with_public_key(const char *buf, const size_t buf_len, const unsigned char *signature, const size_t sig_len)
{
	unsigned char md[ASD_SHA256_LEN + 1];
	RSA *pubRSA = NULL;
	int verified = 0;

#ifdef ASD_DEBUG
        return ASD_SUCCESS; //always return ASD_SUCCESS to skip signature verify.
#endif

	if(!buf || !signature)
		return ASD_FAIL;

	pubRSA = _read_public_key();
	if(!pubRSA)
	{
		ASD_DBG("[%s]_read_public_key fail!\n", __FUNCTION__);
		return ASD_FAIL;
	}
	
	memset(md, 0, sizeof(md));
	SHA256(buf, buf_len, md);			
	
	verified = RSA_verify(NID_sha256, md, ASD_SHA256_LEN, signature, sig_len, pubRSA);
	RSA_free(pubRSA);

	return verified == 1? ASD_SUCCESS: ASD_FAIL;
}

/*******************************************************************
* NAME: verify_file
* AUTHOR: Andy Chiu
* CREATE DATE: 2019/12/18
* DESCRIPTION: verify the local file with public key
* INPUT:  file: string, the path of the file.
*         verline: string, If it's not NULL, must compare the first line of the file by this variable.
* 	      file_enc: bool number, If 1, decrypt the file content. 
* OUTPUT:  None
* RETURN: ASD_SUCCESS or ASD_FAIL 
* NOTE:
*******************************************************************/
int verify_file(const char *file, const char *verline, const int file_enc)
{
	size_t sz;
	unsigned char *message = NULL, signature[ASD_SIG_LEN + 1], *p;
	FILE *fp;
	int verified = ASD_FAIL;

	if(!file || access(file, F_OK) == -1)
		return verified;

	message = read_file(file, 1, file_enc);
	
	//check verline
	if(!message)
	{
		ASD_DBG("[%s] Cannot read the file(%s)\n", __FUNCTION__, file);
		return verified;
	}
	else if(verline)
	{
		p = strchr(message, '\n');
		if(p)
		{
			*p = '\0';
			if(!strcmp(message, verline))
				verified = ASD_SUCCESS;
		}
	}
	else
	{
		verified = ASD_SUCCESS;
	}

	SAFE_FREE(message);
	return verified;
	
}

/*******************************************************************
* NAME: get_feature_list_from_version
* AUTHOR: Andy Chiu
* CREATE DATE: 2019/12/18
* DESCRIPTION: read the (backup) version file and get the feature version information
* INPUT:  from: ASD_DATA_FROM_FILE or ASD_DATA_FROM_BK_FILE
*         size: the array size of feature_info
* OUTPUT:  feature_info: array of FEATURE_INFO
* RETURN: ASD_SUCCESS or ASD_FAIL 
* NOTE:
*******************************************************************/
int get_feature_list_from_version(const int from, FEATURE_INFO *feature_info, const size_t size)
{
	int i;
	char *addr, *buf = NULL, *pch;
	const char *path = NULL;
	char name[ASD_MAX_NAME_LEN], ver[ASD_MAX_VERSION_LEN];
	
	if(!feature_info)
		return ASD_FAIL;

	//load data from file
	if(ASD_DATA_FROM_FILE == from ||
		ASD_DATA_FROM_BK_FILE == from)
	{
		path = (ASD_DATA_FROM_FILE == from)? local_ver_path[0]: local_ver_bk_path[0];
#ifdef ASD_DEBUG
                buf = read_file(path, 1, 0);
#else
                buf = read_file(path, 1, 1);
#endif
		if(!buf)
		{
			ASD_DBG("[%s]Cannnot read file(%s)\n", __FUNCTION__, path);
			return ASD_FAIL;
		}
	}
	else
		return ASD_FAIL;

	//parse the data and set into feature_info array list.
	pch = strtok(buf, "\n");
	i = 0;
	while(pch)
	{
		if(sscanf(pch, "%s %s", name, ver) == 2)
		{
			if(i < size)
			{
				strlcpy((feature_info + i)->name, name, ASD_MAX_NAME_LEN);
				strlcpy((feature_info + i)->version, ver, ASD_MAX_VERSION_LEN);
				++i;
			}
			if(i >= size)
				break;
		}
		pch = strtok(NULL, "\n");
	}
		
	SAFE_FREE(buf);
	return i;
}

/*******************************************************************
* NAME: _convert_ascii_to_hex
* AUTHOR: Andy Chiu
* CREATE DATE: 2019/12/25
* DESCRIPTION: convert the ascii string to hex char[]
* INPUT:  ascii_str: string, The string needs to be converted.
*         ascii_len: unsigned number, the length of the ascii_str.
*		  hex_len: unsigned number, the size of the hex_str buffer.
* OUTPUT:  hex_str: string. The result string of the conversion.
* RETURN: If success, return the pointer of hex_str. If not, return NULL.
* NOTE:
*******************************************************************/
static char *_convert_ascii_to_hex(const char *ascii_str, const size_t ascii_len, char *hex_str, const hex_len)
{
	int i;

	if(!ascii_str || !hex_str || hex_len <= (ascii_len * 2))	//hex_str need a end-string character in its array.
		return NULL;
	
	for(i = 0; i < ascii_len; ++i)
	{
		sprintf(hex_str + (i * 2), "%02X", ascii_str[i]);
	}
	return hex_str;
}

/*******************************************************************
* NAME: _convert_hex_to_ascii
* AUTHOR: Andy Chiu
* CREATE DATE: 2019/12/25
* DESCRIPTION: convert the hex string to ascii string
* INPUT:  hex_str: string, The string needs to be converted.
*		  hex_len: unsigned number, the length of the hex_str string.
*         ascii_len: unsigned number, the size of the ascii_str buffer.
* OUTPUT:  ascii_str: string. The result string of the conversion.
* RETURN: If success, return the pointer of ascii_str. If not, return NULL.
* NOTE:
*******************************************************************/
static char *_convert_hex_to_ascii(const char *hex_str, const hex_len, char *ascii_str, const size_t ascii_len)
{
	int i, j;
	char hex[5] = {'0', 'x', '0', '0', '\0'}, *end;

	if(!ascii_str || !hex_str || ascii_len <= (hex_len / 2))	//ascii_str need a end-string character in its array.
		return NULL;
	
	for(i = 0, j = 0; i < hex_len; i += 2, ++j)
	{
		hex[2] = hex_str[i];
		hex[3] = hex_str[i + 1];
		ascii_str[j] = strtol(hex, &end, 16);
	}
	return ascii_str;
}


/*******************************************************************
* NAME: _verify_hex_str
* AUTHOR: Andy Chiu
* CREATE DATE: 2020/1/17
* DESCRIPTION: Verify the hex_string. Only 0~9, A~F, a~f are valid.
* INPUT:  str: hex string
*               len: length of str
* OUTPUT:  None
* RETURN: ASD_SUCCESS or ASD_FAIL
* NOTE:
*******************************************************************/
static int _verify_hex_str(const char *str, const size_t len)
{
    int i;
    
    if(str)
    {
        for(i = 0; i < len; ++i)
        {
            if((str[i] < '0' || str[i] > '9') &&  //check number
                (str[i] <'A' || str[i] > 'F') &&    //check A~F
                (str[i] < 'a' || str[i] > 'f')) //check a~f
                return ASD_FAIL;
        }
        return ASD_SUCCESS;
    }
    return ASD_FAIL;
}

/*******************************************************************
* NAME: read_file
* AUTHOR: Andy Chiu
* CREATE DATE: 2019/12/18
* DESCRIPTION: Verify and read the file and return the content without signature. 
*			   If need, decrypt the file contnet.
* INPUT:  file: string, path of the file.
*         check_sig: bool number. If 1, need to check the signature of the file.
*		  file_enc: bool number, If 1, need to decrypt the content of the file.
* OUTPUT:  None
* RETURN: The decrypted content of the file without signature.
* NOTE:
*******************************************************************/
char *read_file(const char *file, const int check_sig, const int file_enc)
{
	char *buf = NULL, *f_buf = NULL, *hex_str = NULL;
	unsigned char sig_buf[ASD_SIG_LEN] = {0};
	FILE *fp;
	unsigned long sz, dec_sz, buf_len;
	
	if(!file)
		return NULL;

	sz = f_size(file);
	if(!sz || (check_sig && sz <= ASD_SIG_LEN))
	{
		ASD_DBG("[%s] File size is invalid (%s)!\n", __FUNCTION__, file);
		return NULL;
	}

	fp = fopen(file, "r");
	if(fp)
	{
		f_buf = calloc(sz, 1);
		if(!f_buf)
		{
			ASD_DBG("[%s] Memory alloc fail!\n", __FUNCTION__);
			fclose(fp);
			return NULL;
		}
		fread(f_buf, 1, check_sig? sz - ASD_SIG_LEN: sz, fp);
		if(check_sig)
			fread(sig_buf, 1, ASD_SIG_LEN, fp);
		fclose(fp);
	}
	else
	{
		ASD_DBG("[%s] Cannot open file (%s)!\n", __FUNCTION__, file);
		return NULL;
	}
	if(file_enc)
	{
		dec_sz = pw_dec_len(f_buf);

		hex_str = calloc(dec_sz + 1, 1);
		if(!hex_str)
		{
			ASD_DBG("[%s] Memory alloc fail!\n", __FUNCTION__);
			SAFE_FREE(f_buf);
			return NULL;
		}

		//decrypt content and verify 
		pw_dec(f_buf, hex_str);
		if(_verify_hex_str(hex_str, strlen(hex_str)) == ASD_FAIL)
		{
			ASD_DBG("[%s] HEX string is invalid!\n", __FUNCTION__);
                      SAFE_FREE(f_buf);
                      return NULL;
		}
        
		//convert hex to ascii
		buf_len = strlen(hex_str) / 2 + 1;
		buf = calloc(buf_len, 1);
		if(!buf)
		{
			ASD_DBG("[%s] Memory alloc fail!\n", __FUNCTION__);
			SAFE_FREE(f_buf);
			SAFE_FREE(hex_str);
			return NULL;
		}

		if(!_convert_hex_to_ascii(hex_str, strlen(hex_str), buf, buf_len))
		{
			ASD_DBG("[%s] _convert_hex_to_ascii fail!\n", __FUNCTION__);
			SAFE_FREE(f_buf);
			SAFE_FREE(buf);
			SAFE_FREE(hex_str);
			return NULL;
		}

		SAFE_FREE(hex_str);
	}
	else
	{
		buf = strdup(f_buf);
		if(!buf)
		{
			ASD_DBG("[%s] Memory alloc fail!\n", __FUNCTION__);
			SAFE_FREE(f_buf);
			return NULL;
		}
	}

	SAFE_FREE(f_buf);

	if(buf[0] != '\0')
	{
		if(check_sig)
		{
			if(_verify_with_public_key(buf, strlen(buf), sig_buf, ASD_SIG_LEN) == ASD_SUCCESS)
			{
				return buf;
			}
		}
		else
		{
			return buf;
		}
	}
	SAFE_FREE(buf);
	return NULL;
}

/*******************************************************************
* NAME: encrypt_file
* AUTHOR: Andy Chiu
* CREATE DATE: 2019/12/18
* DESCRIPTION: encrypted the file content and save it with the signature as another file.
* INPUT:  src_file: string, the path of the source file.
*         dst_file: string, the path of the destination file.
*         with_sig: bool number, if 1, the src file include signature data, on need to encrypted it. Just need to copy it to the destination file.
* OUTPUT:  None
* RETURN: ASD_SUCCESS or ASD_FAIL 
* NOTE:
*******************************************************************/
int encrypt_file(const char *src_file, const char *dst_file, const int with_sig)
{
	unsigned long src_sz, dst_sz, hex_len;
	unsigned char sig_buf[ASD_SIG_LEN];
	char *src_buf = NULL, *dst_buf = NULL, *hex_str = NULL;
	FILE *fp;
	int ret = ASD_FAIL;
	
	if(!src_file || !dst_file)
		return ret;
	
	//read file content
	src_sz = f_size(src_file);
	
	if(!src_sz || (with_sig && src_sz <= ASD_SIG_LEN))
	{
		ASD_DBG("[%s] File size is invalid (%s)!\n", __FUNCTION__, src_file);
		return ret;
	}
	
	if(with_sig)
		src_sz -= ASD_SIG_LEN;
	
	fp = fopen(src_file, "r");		
	if(fp)
	{
		src_buf = calloc(src_sz + 1, 1);
		if(!src_buf)
		{
			ASD_DBG("[%s] Memory alloc fail!\n", __FUNCTION__);
			fclose(fp);
			return ret;
		}
		fread(src_buf, 1, src_sz, fp);
		if(with_sig)
			fread(sig_buf, 1, ASD_SIG_LEN, fp);
		fclose(fp);
	}
	else
	{
		ASD_DBG("[%s] Cannot open file (%s)!\n", __FUNCTION__, src_file);
		return ret;
	}	
	
	//convert file content to hex string
	hex_len = src_sz * 2 + 1;
	hex_str = calloc(hex_len, 1);
	if(!hex_str)
	{
		ASD_DBG("[%s] Memory alloc fail!\n", __FUNCTION__);
		SAFE_FREE(src_buf);
		return ret;
	}
	
	if(!_convert_ascii_to_hex(src_buf, src_sz, hex_str, hex_len))
	{
		ASD_DBG("[%s] _convert_ascii_to_hex fail!\n", __FUNCTION__);
		SAFE_FREE(hex_str);
		SAFE_FREE(src_buf);
		return ret;
	}

	//the original file content would not be used, free it.
	SAFE_FREE(src_buf);

	//encrypt the hex string
	dst_sz = pw_enc_blen(hex_str);

	dst_buf = calloc(dst_sz + 1, 1);
	if(!dst_buf)
	{
		ASD_DBG("[%s] Memory alloc fail!\n", __FUNCTION__);
		SAFE_FREE(hex_str);
		return ret;
	}
	
	pw_enc(hex_str, dst_buf);
	
	if(dst_buf[0] != '\0')
	{
		fp = fopen(dst_file, "w");
		if(fp)
		{
			fwrite(dst_buf, 1, strlen(dst_buf), fp);
			if(with_sig)
				fwrite(sig_buf, 1, ASD_SIG_LEN, fp);
				
			fclose(fp);
			ret = ASD_SUCCESS;
		}
		else
		{
			ASD_DBG("[%s] Cannot open file (%s)!\n", __FUNCTION__, dst_file);
		}
	}
	else
	{
		ASD_DBG("[%s] Cannot encrypt content.\n", __FUNCTION__);
	}
	
	SAFE_FREE(hex_str);
	SAFE_FREE(dst_buf);
	return ret;
}


//A bad method for the urgent release.
//Need to modify by json format.
int blockfile_rule_hit[1024];
int chknvram_rule_hit[1024];

void reset_rule_hit()
{
    //ASD_DBG("[%s]\n", __FUNCTION__);
    memset(blockfile_rule_hit, 0, sizeof(blockfile_rule_hit));
    memset(chknvram_rule_hit, 0, sizeof(chknvram_rule_hit));
}

/*
example:[{\"blockfile\":[{\"1\":\"2\"},{\"3\":\"5\"}]},{\"chknvram\":[{\"1\":\"1\"}]}]
*/

int save_rule_hit()
{
    FILE *fp;
    char buf[2048] = {0};
    int i, cnt, flag = 0, blockfile_flag = 0, chknvram_flag = 0;

    //check rule hit to decide which feature needed to be recorded in the log file.
    for(i = 0; i < 1024; ++i)
    {
        if(blockfile_rule_hit[i] > 0)
        {
            blockfile_flag = 1;
        }

        if(chknvram_rule_hit[i] > 0)
        {
            chknvram_flag = 1;
        }

        if(blockfile_flag && chknvram_flag)
            break;
    }

    if(blockfile_flag || chknvram_flag)
    {
        fp = fopen(asd_json_log_path[0], "w");
        if(fp)
        {
            //the begin character, "[" of json array
            snprintf(buf, sizeof(buf), "[");

            if(blockfile_flag)
            {
                snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "{\"%s\":[", blockfile_name[0]);
                for(i = 0, cnt = 0; i < 1024; ++i)
                {
                    if(blockfile_rule_hit[i] > 0)
                    {
                        snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), cnt? ",{\"%d\":\"%d\"}":"{\"%d\":\"%d\"}", i, blockfile_rule_hit[i]);
                        ++cnt;                
                    }
                }
                snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "]}");
            }

            if(chknvram_flag)
            {
                snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), blockfile_flag? ",{\"%s\":[":"{\"%s\":[", chknvram_name[0]);
                for(i = 0, cnt = 0; i < 1024; ++i)
                {
                    if(chknvram_rule_hit[i] > 0)
                    {
                        snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), cnt? ",{\"%d\":\"%d\"}":"{\"%d\":\"%d\"}", i, chknvram_rule_hit[i]);
                        ++cnt;                
                    }
                }
                snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "]}");
            }
            
            //the end character of json
            snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "]");

            fwrite(buf, 1, strlen(buf), fp);
            
            fclose(fp);
            return ASD_SUCCESS;
        }
    }
    else
        return ASD_SUCCESS;
    
    return ASD_FAIL;
}

