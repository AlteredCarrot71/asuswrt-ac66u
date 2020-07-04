#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <shared.h>

#include "security_daemon.h"
#include "feature_def.h"
#include "signature.h"
#include "utility.h"

#define OUTPUT_DNS_IN_OUTPUT_CHAIN_NUM	2

//Example: |10|poiuytyuiopkjfnf|03|com|00| ==> |10706f697579747975696f706b6a666e6603636f6d00|
static char* _convert_hex_string(const char* src)
{
	char *dst = NULL;
	size_t len;
	int i, j, cnt = 0, dst_len = 0, src_len, flag;
	
	if(!src)
		return NULL;

	//count the converted string length
	//each pair of '|' contains a set of 16-digit number, count the number of '|'
	src_len = strlen(src);
	for(i = 0; i < src_len; ++i)
	{
		if(src[i] == '|')	
			++cnt;
	}

	if(cnt % 2 == 1)	//'|' cannot be odd number
	{
		ASD_DBG("[%s]DNS hex string is invalid.\n", __FUNCTION__);
		return NULL;
	}

	dst_len = cnt + ((src_len - (cnt * 2)) * 2) + 2;

	//alloc the dst buffer
	dst = calloc(dst_len + 1, 1);

	dst[0] = '|';	//the first character must be '|'
	flag = 0;
	for(i = 0, j = 1; i < src_len; ++i)
	{
		if(src[i] == '|')
		{
			flag = flag? 0: 1;
			continue;
		}

		if(flag)	//length, assign directly
		{
			//length characters only support 16-digit
			//convert uppercase to lowercase
			if(src[i] >= 'A' && src[i] <= 'F')
				dst[j] = src[i] - 'A' + 'a';	
			else
				dst[j] = src[i];
			++j;
		}
		else
		{
			//convert char to hex string
			snprintf(dst + j, dst_len - j, "%02x", src[i]);
			j += 2;
		}
	}
	dst[j] = '|';	//the last character must be '|'
	dst[j + 1] = '\0';
	return dst;
}

int blockdns_action()
{
	char buf[512];
	CONTENT_BY_LINE sig, curiptable;
	int i, j, flag = 0, cnt;
	char *p;
	
	//init variables
	memset(&sig, 0, sizeof(CONTENT_BY_LINE));
	memset(&curiptable, 0, sizeof(CONTENT_BY_LINE));

#ifdef SUPPORT_ASD_SHM
	//read the feature signature file
	if(read_shm_in_content(blockdns_name[0], &sig) != ASD_FAIL)
	{			
		//get whole iptables
		snprintf(buf, sizeof(buf), "iptables-save > %s", cur_iptables[0]);
		system(buf);

		//check OUTPUT chain
		if(read_file_in_content(cur_iptables[0], "-A OUTPUT ", &curiptable) != ASD_FAIL)
		{
			cnt = 0;
			for(i = 0; i < curiptable.num; ++i)
			{
				if(strstr(curiptable.line[i], "-j OUTPUT_DNS"))
				{
					++cnt;
				}
			}
			free_content(&curiptable);
			if(cnt != OUTPUT_DNS_IN_OUTPUT_CHAIN_NUM) //rule number is not matched
			{
				flag = 1;
				ASD_DBG("[%s]Some wrong in iptables OUTPUT chain! Rule number is not expected.\n cnt (%d) OUTPUT_DNS_IN_OUTPUT_CHAIN_NUM (%d)\n", __FUNCTION__, cnt, OUTPUT_DNS_IN_OUTPUT_CHAIN_NUM);
			}
		}
		
		//check OUTPUT_DNS chain
		if(!flag)
		{
			if(read_file_in_content(cur_iptables[0], "-A OUTPUT_DNS", &curiptable) != ASD_FAIL)
			{
				for(i = 0; i < curiptable.num; ++i)
				{
					for(j = 1; j < sig.num; ++j)	//ignore the first line, it's version.
					{
						p = _convert_hex_string(sig.line[j]);
						if(!p)
							continue;
						snprintf(buf, sizeof(buf), "--hex-string \"%s\"", p);
						SAFE_FREE(p);
						if(strstr(curiptable.line[i], buf) && strstr(curiptable.line[i], "-j logdrop_dns"))
						{
							sig.checked[j] = 1;
							break;
						}
					}
					if(j == sig.num)	//Unexpected rule in OUTPUT_IP chain.
					{
						flag = 1;
						ASD_DBG("[%s]Some wrong in iptables OUTPUT_DNS chain! Unexpected rule in OUTPUT_DNS chain.\n", __FUNCTION__);
						break;
					}
				}
				free_content(&curiptable);
			}

			for(i = 1; i < sig.num; ++i)
			{
				if(!sig.checked[i])
				{
					flag = 1;
					ASD_DBG("[%s]Some wrong in iptables OUTPUT_DNS chain!  Expected rule is NOT found in OUTPUT_DNS chain.\n", __FUNCTION__);
					break;
				}
			}
			free_content(&sig);
		}
		unlink(cur_iptables[0]);
		
		if(flag)
		{
			//restart firewall
			ASD_DBG("[%s]Restart firewall!\n", __FUNCTION__);
			system("service restart_firewall");
			sleep(1);
		}
			
	}		
#endif
	return ASD_SUCCESS;
}

int blockdns_priod(const long now)
{
	blockdns_action();
	return ASD_SUCCESS;
}


int blockdns_init(void){
	FEATURE_DEFINE feature={
			.name = blockdns_name[0],
			.period = 30,
			.last_period_call = 0,
			.action = blockdns_action,
			.period_func = blockdns_priod,
	};
	return register_feature(&feature);
}

