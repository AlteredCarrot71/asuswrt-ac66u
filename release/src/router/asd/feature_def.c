#include <stdio.h>
#include <stdlib.h>

#include <shared.h>

#include "security_daemon.h"
#include "feature_def.h"

unsigned int feature_list_size = 0;
FEATURE_DEFINE *feature_list = NULL;

//extern int blockip_init(void);
//extern int blockdns_init(void);
extern int blockfile_init(void);
extern int chknvram_init(void);

//Andy Chiu, 2019/12/11. Only support blockfile at the first phase.	
feature_init init_table[] = 
{
//	blockip_init,
//	blockdns_init,
	blockfile_init,
	chknvram_init,
	NULL,
};

/*******************************************************************
* NAME: feature_list_init
* AUTHOR: Andy Chiu
* CREATE DATE: 2019/12/18
* DESCRIPTION: init the global feature list
* INPUT:  None
* OUTPUT:  None
* RETURN:  ASD_SUCCESS or ASD_FAIL
* NOTE:
*******************************************************************/
int feature_list_init()
{
	int i;

	//count the member count of the feaure list 
	for(i = 0;; ++i)
	{
		if(init_table[i] == NULL)
			break;
	}

	feature_list_size = i + 1;

	//alloc feature_list
	feature_list = calloc(feature_list_size, sizeof(FEATURE_DEFINE));
	if(!feature_list)
	{
		ASD_DBG("[%s]Memory alloc for feature_list fail!\n", __FUNCTION__);
		return ASD_FAIL;
	}

	//init feature list
	for(i = 0; i < feature_list_size - 1; ++i)
	{
		if(init_table[i]() != ASD_SUCCESS)
		{
			ASD_DBG("[%s]Init fail at index %d\n", __FUNCTION__, i);
			SAFE_FREE(feature_list);
			return ASD_FAIL;
		}
	}
	return ASD_SUCCESS;
}

/*******************************************************************
* NAME: register_feature
* AUTHOR: Andy Chiu
* CREATE DATE: 2019/12/18
* DESCRIPTION: a callback function for a new feature to register in the global feature list
* INPUT:  feature: pointer of FEATURE_DEFINE
* OUTPUT:  None
* RETURN:  ASD_SUCCESS or ASD_FAIL
* NOTE:
*******************************************************************/
int register_feature(FEATURE_DEFINE *feature)
{
	static int index=0;

	if(!feature)
		return ASD_FAIL;

	if(index >= feature_list_size)
	{
		ASD_DBG("[%s]The number of feature is out of feature_list_size!\n", __FUNCTION__);
		return ASD_FAIL;
	}
	else
	{
		ASD_DBG("[%s] %s registed \n", __FUNCTION__, feature->name);
		memcpy((feature_list + index), feature, sizeof(FEATURE_DEFINE));
		index++;
		return ASD_SUCCESS;
	}
}
	
/*******************************************************************
* NAME: find_feature
* AUTHOR: Andy Chiu
* CREATE DATE: 2019/12/18
* DESCRIPTION: find a feature in the global feature list by name.
* INPUT:  name: string of the feature name
* OUTPUT:  None
* RETURN:  the pointer of FEATURE_DEFINE. If not found, return NULL.
* NOTE:
*******************************************************************/
FEATURE_DEFINE* find_feature(const char *name)
{
	int i;
	
	if(!name)
		return NULL;
	
	for(i = 0; i < feature_list_size - 1; ++i)
	{
		if(feature_list[i].name && !strcmp(name, feature_list[i].name))
			return &feature_list[i];
	}
	return NULL;
}

/*******************************************************************
* NAME: get_feature_by_index
* AUTHOR: Andy Chiu
* CREATE DATE: 2019/12/18
* DESCRIPTION: find a feature in the global feature list by index.
* INPUT:  index: number of the feature list index
* OUTPUT:  None
* RETURN:  the pointer of FEATURE_DEFINE. If not found, return NULL.
* NOTE:
*******************************************************************/
FEATURE_DEFINE *get_feature_by_index(const int index)
{
	static int cur_idx = 0;

	if(index == NEXT_FEATURE && cur_idx < feature_list_size - 2)
	{
		++cur_idx;
		return feature_list + cur_idx;
	}
	else if(index < feature_list_size -1)
	{
		cur_idx = index;
		return feature_list +cur_idx;
	}
	return NULL;
}

/*******************************************************************
* NAME: do_feature_period
* AUTHOR: Andy Chiu
* CREATE DATE: 2019/12/18
* DESCRIPTION: Check the feature period time and call the period function.
* INPUT:  None
* OUTPUT:  None
* RETURN:    ASD_SUCCESS or ASD_FAIL
* NOTE:
*******************************************************************/
int do_feature_period()
{
	int i;
	long now = uptime();
	for(i = 0; i < feature_list_size; ++i)
	{
		if(feature_list[i].period_func && 
			(now - feature_list[i].last_period_call >= feature_list[i].period))
		{
			feature_list[i].period_func(now);
			feature_list[i].last_period_call = now;
		}
	}
	return ASD_SUCCESS;
}

/*******************************************************************
* NAME: update_signature_in_feature
* AUTHOR: Andy Chiu
* CREATE DATE: 2019/12/18
* DESCRIPTION: Update the sig_buf and version in the FEATURE_DEFINE structure.
* INPUT:  name: string, name of the feature. version: string, version of the signature file.
* OUTPUT:  None
* RETURN:    ASD_SUCCESS or ASD_FAIL
* NOTE:
*******************************************************************/
int update_signature_in_feature(const char *name, const char *version)
{
	char path[256];
	FEATURE_DEFINE *fd = NULL;
	char *data;
	
	if(!name || !version)
		return ASD_FAIL;
	
	fd = find_feature(name);
	if(fd)
	{
		//get full signature file path and read it.
		snprintf(path, sizeof(path), "%s/%s%s", local_asd_dir[0], name, version);
#ifdef ASD_DEBUG
		data = read_file(path, 1, 0);            
#else
		data = read_file(path, 1, 1);
#endif
		if(data)
		{
			SAFE_FREE(fd->sig_buf);
			fd->sig_buf = data;
			strlcpy(fd->sig_ver, version, sizeof(fd->sig_ver));
			ASD_DBG("[%s] Update sig in feature(%s)\n", __FUNCTION__, name);
			return ASD_SUCCESS;
		}
		else
		{
			ASD_DBG("[%s] Cannot update signature (%s%s)\n", __FUNCTION__, name, version);
		}
	}
	return ASD_FAIL;
}

/*******************************************************************
* NAME: update_signature_in_all_feature
* AUTHOR: Andy Chiu
* CREATE DATE: 2019/12/18
* DESCRIPTION: Update the sig_buf for all features by version file.
* INPUT:  None
* OUTPUT:  None
* RETURN:    ASD_SUCCESS or ASD_FAIL
* NOTE:
*******************************************************************/
int update_signature_in_all_feature()
{
	FEATURE_INFO feature_info[ASD_MAX_FEATURE_NUM];
	int cnt = 0, i, ret = ASD_SUCCESS;
	
	memset(feature_info, 0, sizeof(feature_info));
    
	cnt = get_feature_list_from_version(ASD_DATA_FROM_FILE, feature_info, ASD_MAX_FEATURE_NUM);
		
	for(i = 0; i < cnt; ++i)
	{
		if(update_signature_in_feature(feature_info[i].name, feature_info[i].version) != ASD_SUCCESS)
		{
			ASD_DBG("[%s] Cannot update signature (%s%s)\n", __FUNCTION__, feature_info[i].name, feature_info[i].version);
			ret = ASD_FAIL;
		}
	}
	return ret;
}
