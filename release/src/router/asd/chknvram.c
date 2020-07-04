#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <shared.h>

#include "security_daemon.h"
#include "feature_def.h"
#include "signature.h"

#define MAX_PARA_NUM_IN_ONE_LINE    3
enum{
    PARA_NVRAM_NAME = 0,
    PARA_VALID_RANGE = 1,
    PARA_ACTION = 1,
    PARA_DEFAULT_VAL = 2
};

const char para_unset_str[] = "unset";

/*******************************************************************
* NAME: chknvram_action
* AUTHOR: Andy Chiu
* CREATE DATE: 2020/1/16
* DESCRIPTION: check if the nvram value is valid. if not, set as default value.
* INPUT:  None
* OUTPUT:  None
* RETURN: ASD_SUCCESS or ASD_FAIL 
* NOTE:
*******************************************************************/
int chknvram_action()
{
    FEATURE_DEFINE *fd;
    char *buf = NULL, *pch, *p2;
    char *val, *tmp, *tmp2, *min_ptr, *max_ptr;
    char *para[MAX_PARA_NUM_IN_ONE_LINE];
    char *saveptr1, *saveptr2, *saveptr3;
    int i = 0, min, max, flag, idx, record_flag = 0;

    if(access(asd_json_log_path[0], F_OK) == -1)
        reset_rule_hit();
    
    fd = find_feature(chknvram_name[0]);
    if(fd && fd->sig_buf)
    {
        buf = strdup(fd->sig_buf);
        if(buf)
        {
            pch = strtok_r(buf, "\n", &saveptr1);
            while(pch)
            {
                if(i)	//ignore the first line, it's version.
                {
                    //format: nvram name!valid range!default value
                    //format2: nvram name!unset     <== this nvram should not exist. If found it, unset it.
                    tmp2 = strdup(pch);
                    if(tmp2)
                    {
                        p2 = strtok_r(tmp2, "!", &saveptr2);
                        idx = 0;
                        memset(para, 0, sizeof(char*) * MAX_PARA_NUM_IN_ONE_LINE);
                        while(p2)
                        {
                            para[idx] = p2;
                            ++idx;
                            if(idx >= MAX_PARA_NUM_IN_ONE_LINE)
                                break;
                            p2 = strtok_r(saveptr2, "!", &saveptr2);
                        }

                        if(para[PARA_NVRAM_NAME] && para[PARA_ACTION] && !strcmp(para[PARA_ACTION], para_unset_str))
                        {
                            if(nvram_get(para[PARA_NVRAM_NAME]))
                            {
                                ASD_DBG("[%s]Unset invalid nvram,<%s>\n", __FUNCTION__, para[PARA_NVRAM_NAME]);
                                nvram_unset(para[PARA_NVRAM_NAME]);
                                chknvram_rule_hit[i] ++;
                                record_flag = 1;
                            }
                        }
                        else if(para[PARA_NVRAM_NAME] && para[PARA_VALID_RANGE] && para[PARA_DEFAULT_VAL])
                        {
                            val = nvram_safe_get(para[PARA_NVRAM_NAME]);
                           if(val[0] != '\0')
                            {
                                //valid range format: 
                                //a string list separated by blackslash. 
                                //ex, 37\18\33\yes\no
                                //a number of range. ex, 100|200
                                tmp = strdup(para[PARA_VALID_RANGE]);
                                if(tmp)
                                {
                                    p2 = strtok_r(tmp, "\\", &saveptr3);
                                    flag = 0;
                                    while(p2)
                                    {
                                        max_ptr = strchr(p2, '|');
                                        if(max_ptr)  //check number range
                                        {
                                            min_ptr = p2;
                                            *max_ptr = '\0';
                                            ++max_ptr;
                                            min = atoi(min_ptr);
                                            max = atoi(max_ptr);
                                            if(atoi(val) >= min && atoi(val) <= max)
                                            {
                                                flag = 1;
                                                break;
                                            }
                                        }
                                       else if(!strcmp(val, p2))    //compare string
                                        {
                                            flag = 1;
                                            break;
                                        }
                                        p2 = strtok_r(saveptr3, "\\", &saveptr3);
                                    }
                                    
                                    if(!flag)
                                    {
                                        ASD_DBG("[%s]Reset invalid nvram,<%s, %s>\n", __FUNCTION__, para[PARA_NVRAM_NAME], val);
                                        nvram_set(para[PARA_NVRAM_NAME], para[PARA_DEFAULT_VAL]);
                                        chknvram_rule_hit[i] ++;
                                        record_flag = 1;
                                    }
                                    SAFE_FREE(tmp);
                                }
                                else
                                {
                                    ASD_DBG("[%s] Cannot duplicate the valid range string.\n", __FUNCTION__);
                                    continue;
                                }
                            }                            
                            else
                            {
                                ASD_DBG("[%s] Cannot duplicate nvram(%s) value.\n", __FUNCTION__, __LINE__, para[PARA_NVRAM_NAME]);
                                continue;
                            }
                        }
                        else
                        {
                            ASD_DBG("[%s] Invalid string\n", __FUNCTION__, __LINE__);
                            continue;
                        }
                        SAFE_FREE(tmp2);
                    }
                    else
                    {
                        ASD_DBG("[%s] Cannot deplicate string.\n", __FUNCTION__, __LINE__);
                        continue;
                    }
                }
                ++i;
                pch = strtok_r(saveptr1, "\n", &saveptr1);
            }
            SAFE_FREE(buf);
        }
        else
        {
            ASD_DBG("[%s] Cannot duplicate signature content.\n", __FUNCTION__);
        }
    }
    if(record_flag)
        save_rule_hit();	

    return ASD_SUCCESS;
}

/*******************************************************************
* NAME: chknvram_period
* AUTHOR: Andy Chiu
* CREATE DATE: 2020/1/16
* DESCRIPTION: period callback function
* INPUT:  None
* OUTPUT:  None
* RETURN: ASD_SUCCESS or ASD_FAIL 
* NOTE:
*******************************************************************/
int chknvram_period(const long now)
{
	chknvram_action();
	return ASD_SUCCESS;
}


/*******************************************************************
* NAME: chknvram_init
* AUTHOR: Andy Chiu
* CREATE DATE: 2020/1/16
* DESCRIPTION: initialize the FEATURE_DEFINE for chknvram feature.
* INPUT:  None
* OUTPUT:  None
* RETURN: ASD_SUCCESS or ASD_FAIL 
* NOTE:
*******************************************************************/
int chknvram_init(void){
	FEATURE_DEFINE feature={
			.name = chknvram_name[0],
			.period = 10,
			.last_period_call = 0,
			.action = chknvram_action,
			.period_func = chknvram_period,
            .sig_ver[0] = '\0',
            .sig_buf = NULL,
	};
        memset(chknvram_rule_hit, 0, sizeof(chknvram_rule_hit));
	return register_feature(&feature);
}






