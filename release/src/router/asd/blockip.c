#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <shared.h>

#include "security_daemon.h"
#include "feature_def.h"
#include "signature.h"
#include "utility.h"

#define OUTPUT_IP_IN_OUTPUT_CHAIN_NUM	1


int blockip_action()
{
	char buf[512];
	CONTENT_BY_LINE sig, curiptable;
	int i, j, flag = 0, cnt = 0;

	//init variable
	memset(&sig, 0, sizeof(CONTENT_BY_LINE));
	memset(&curiptable, 0, sizeof(CONTENT_BY_LINE));

#ifdef SUPPORT_ASD_SHM
	//read the feature signature file
	if(read_shm_in_content(blockip_name[0], &sig) != ASD_FAIL)
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
				if(strstr(curiptable.line[i], "-j OUTPUT_IP"))
				{
					++cnt;
				}
			}
			free_content(&curiptable);
			if(cnt != OUTPUT_IP_IN_OUTPUT_CHAIN_NUM) //rule not found
			{
				flag = 1;
				ASD_DBG("[%s]Some wrong in iptables OUTPUT chain!  Rule number is not expected.\n cnt (%d) OUTPUT_IP_IN_OUTPUT_CHAIN_NUM (%d)\n", __FUNCTION__, cnt, OUTPUT_IP_IN_OUTPUT_CHAIN_NUM);
			}
		}

		//check OUTPUT_IP chain
		if(!flag)
		{
			if(read_file_in_content(cur_iptables[0], "-A OUTPUT_IP", &curiptable) != ASD_FAIL)
			{
				for(i = 0; i < curiptable.num; ++i)
				{
					for(j = 1; j < sig.num; ++j)	//ignore the first line, it's version.
					{
						snprintf(buf, sizeof(buf), "-d %s", sig.line[j]);
						if(strstr(curiptable.line[i], buf) && strstr(curiptable.line[i], "-j logdrop_ip"))
						{
							sig.checked[j] = 1;
							break;
						}
					}
					if(j == sig.num)	//rule not found in OUTPUT_IP chain
					{
						flag = 1;
						ASD_DBG("[%s]Some wrong in iptables OUTPUT_IP chain!  Unexpected rule (%d) in OUTPUT_IP chain.\n %s\n", __FUNCTION__, i, curiptable.line[i]);
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
					ASD_DBG("[%s]Some wrong in iptables OUTPUT_IP chain!  Expected rule is NOT found in OUTPUT_IP chain.\n", __FUNCTION__);
						snprintf(buf, sizeof(buf), "cp -f %s %s.1", cur_iptables[0], cur_iptables[0]);
						system(buf);
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

int blockip_priod(const long now)
{
	blockip_action();
	return ASD_SUCCESS;
}


int blockip_init(void){
	FEATURE_DEFINE feature={
			.name = blockip_name[0],
			.period = 30,
			.last_period_call = 0,
			.action = blockip_action,
			.period_func = blockip_priod,
	};
	return register_feature(&feature);
}

