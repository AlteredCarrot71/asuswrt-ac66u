#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <shared.h>

#include "security_daemon.h"
#include "feature_def.h"
#include "signature.h"


/*******************************************************************
* NAME: blockfile_action
* AUTHOR: Andy Chiu
* CREATE DATE: 2019/12/18
* DESCRIPTION: check the file system to remove harmful files by signature file.
* INPUT:  None
* OUTPUT:  None
* RETURN: ASD_SUCCESS or ASD_FAIL 
* NOTE:
*******************************************************************/
int blockfile_action()
{
    FEATURE_DEFINE *fd;
    char *buf = NULL, *pch;
    char path[512];
    int i = 0, flag = 0;

    if(access(asd_json_log_path[0], F_OK) == -1)
        reset_rule_hit();

    fd = find_feature(blockfile_name[0]);
    if(fd && fd->sig_buf)
    {
        buf = strdup(fd->sig_buf);
        if(buf)
        {
            pch = strtok(buf, "\n");
            while(pch)
            {
                if(i)	//ignore the first line, it's version.
                {
                    if(pch[0] != '/')
                    {
                        //check the file system
                        snprintf(path, sizeof(path), "%s/%s", local_folder[0], pch);
                    }
                    else
                    {
                        //check full path
                        strlcpy(path, pch, sizeof(path));
                    }

                    if (f_exists(path))
                    {
                        ASD_DBG("[%s]Delete harmful file,%s\n", __FUNCTION__, path);
                        unlink(path);
                        blockfile_rule_hit[i] ++;
                        flag = 1;
                    }
                }
                ++i;
                pch = strtok(NULL, "\n");
            }
            SAFE_FREE(buf);
        }
        else
        {
            ASD_DBG("[%s] Cannot duplicate signature content.\n", __FUNCTION__);
        }
    }

    if(flag)
        save_rule_hit();	
    return ASD_SUCCESS;
}

/*******************************************************************
* NAME: blockfile_period
* AUTHOR: Andy Chiu
* CREATE DATE: 2019/12/18
* DESCRIPTION: period callback function
* INPUT:  None
* OUTPUT:  None
* RETURN: ASD_SUCCESS or ASD_FAIL 
* NOTE:
*******************************************************************/
int blockfile_period(const long now)
{
	blockfile_action();
	return ASD_SUCCESS;
}


/*******************************************************************
* NAME: blockfile_init
* AUTHOR: Andy Chiu
* CREATE DATE: 2019/12/18
* DESCRIPTION: initialize the FEATURE_DEFINE for blockfile feature.
* INPUT:  None
* OUTPUT:  None
* RETURN: ASD_SUCCESS or ASD_FAIL 
* NOTE:
*******************************************************************/
int blockfile_init(void){
	FEATURE_DEFINE feature={
			.name = blockfile_name[0],
			.period = 10,
			.last_period_call = 0,
			.action = blockfile_action,
			.period_func = blockfile_period,
            .sig_ver[0] = '\0',
            .sig_buf = NULL,
	};
    
        memset(blockfile_rule_hit,  0, sizeof(blockfile_rule_hit));
	return register_feature(&feature);
}





