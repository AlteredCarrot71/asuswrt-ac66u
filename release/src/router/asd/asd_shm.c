#include<stdio.h>
#include<sys/types.h>
#include<sys/ipc.h>
#include<sys/shm.h>
#include <unistd.h>

#include <shared.h>

#include "security_daemon.h"

#ifdef SUPPORT_ASD_SHM
const ASD_SHM_MAP asd_map[] =
{
	{ASD_SHM_KEY_VERSION, ASD_SHM_SIZE_VERSION, version_name[0]},
	{ASD_SHM_KEY_BLKDNS, ASD_SHM_SIZE_BLKDNS, blockdns_name[0]},
	{ASD_SHM_KEY_BLKIP, ASD_SHM_SIZE_BLKIP, blockip_name[0]},
	{ASD_SHM_KEY_BLKFILE, ASD_SHM_SIZE_BLKFILE, blockfile_name[0]},
	{ASD_SHM_KEY_PUBLIC_KEY, ASD_SHM_SIZE_PUBLIC_KEY, publickey_name[0]},
	{ASD_SHM_KEY_INVALID, 0, NULL},
};

static unsigned int _find_size_by_key(const unsigned int key)
{
	int i;
	for(i = 0; asd_map[i].key != ASD_SHM_KEY_INVALID; ++i)
	{
		if(asd_map[i].key == key)
			return asd_map[i].size;
	}
	return 0;
}

static ASD_SHM_MAP* _find_shm_map_by_name(const char *name)
{	
	int i;
	if(!name)
		return NULL;

	for(i = 0; asd_map[i].key != ASD_SHM_KEY_INVALID; ++i)
	{
		if(!strcmp(asd_map[i].name, name))
			return &(asd_map[i]);
	}
	return NULL;
}

const char* find_name_by_shm_key(const unsigned int key)
{
	int i;
	for(i = 0; asd_map[i].key != ASD_SHM_KEY_INVALID; ++i)
	{
		if(asd_map[i].key == key)
			return asd_map[i].name;
	}
	return NULL;
}

const unsigned int find_shm_key_by_name(const char *name)
{
	int i;
	if(!name)
		return 0;

	for(i = 0; asd_map[i].key != ASD_SHM_KEY_INVALID; ++i)
	{
		if(!strcmp(asd_map[i].name, name))
			return asd_map[i].key;
	}
	return 0;	
}
//share memory include the following content.
int load_file_in_shm(const char *file, const int key, const int with_sig)
{
	int shmid = 0;
	unsigned int shm_sz = _find_size_by_key(key);
	unsigned long file_sz;
	char *addr = NULL;
	const char*name;
	FILE *fp;

	if(!file || access(file, F_OK) == -1)
	{
		ASD_DBG("[%s] file not exist!\n", __FUNCTION__);
		return ASD_FAIL;
	}

	if(!shm_sz)
	{
		ASD_DBG("[%s] shm key is invalid!\n", __FUNCTION__);
		return ASD_FAIL;
	}
	
	//count the share memory size
	file_sz = f_size(file);
	
	if(with_sig && file_sz <= ASD_SIG_LEN)
		return ASD_FAIL;

	file_sz = with_sig? (file_sz - ASD_SIG_LEN): file_sz;
	if(file_sz >= shm_sz)
	{
		ASD_DBG("[%s] File (%s) size is bigger than shm size.\n", __FUNCTION__, file);
		return ASD_FAIL;
	}

	//create the share memory
	shmid = shmget((key_t)key, shm_sz, 0666/* | IPC_CREAT*/);
	if(shmid == -1)
	{
		name = find_name_by_shm_key(key);
		ASD_DBG("[%s] share memory (%s) not created.\n", __FUNCTION__, name? name: "");
		return ASD_FAIL;
	}

	addr = shmat(shmid, NULL, 0);
	if(addr)
	{
		memset(addr, 0, shm_sz);
		
		fp = fopen(file, "r");
		if(fp)
		{
			fread(addr, 1, file_sz, fp);
			fclose(fp);
			shmdt(addr);
			ASD_DBG("[%s] Update share memory by %s\n", __FUNCTION__, file);
		}
		else
		{
			ASD_DBG("[%s] Cannot load file (%s) in share memory.\n", __FUNCTION__, file);			
			shmdt(addr);
			return ASD_FAIL;
		}
	}
	else
	{
		shmctl(shmid,IPC_RMID,NULL);
		name = find_name_by_shm_key(key);
		ASD_DBG("[%s] Cannot address share memory(%s).\n", __FUNCTION__, name? name: "");
		return ASD_FAIL;
	}
	return ASD_SUCCESS;
}

int is_shm_created(const int key)
{
	int shm_sz = _find_size_by_key(key);
	int shmid;

	if(shm_sz)
		return ASD_FAIL;
	
	shmid = shmget(key, shm_sz, 0666);
	return (shmid == -1)? ASD_FAIL: ASD_SUCCESS;
}

int is_shm_empty(const int key)
{
	unsigned int shm_sz = _find_size_by_key(key);
	int shmid, ret = ASD_FAIL;
	char *addr;

	if(!shm_sz)
		return ASD_FAIL;

	shmid = shmget(key, shm_sz, 0666);
	if(shmid == -1)	
		return ASD_FAIL;

	addr = shmat(shmid, NULL, 0);
	if(addr)
	{
		if(addr[0] == '\0')
			ret = ASD_SUCCESS;
		shmdt(addr);
	}
	return ret;
}
	
int init_shm()
{
	int i, ret = ASD_SUCCESS, cnt;
	char ver[64], path[256];
	FEATURE_INFO feature_info[ASD_MAX_FEATURE_NUM];
	ASD_SHM_MAP *shm_map;

	//init version	
	if(verify_download_file(local_ver_path[0], NULL) == ASD_SUCCESS)
	{
		//load version file in share memory
		if(load_file_in_shm(local_ver_path[0], ASD_SHM_KEY_VERSION, 1) == ASD_SUCCESS)
		{
			cnt = get_feature_list_from_version(ASD_DATA_FROM_SHM, feature_info, ASD_MAX_FEATURE_NUM);
			
			//load the signature files of other features in the share memory
			for(i = 0; i < cnt; ++i)
			{
				shm_map = _find_shm_map_by_name(feature_info[i].name);

				if(shm_map)
				{
					//get the signature file path of the feature
					snprintf(path, sizeof(path), "%s/%s%s", local_asd_dir[0], feature_info[i].name, feature_info[i].version);
					snprintf(ver, sizeof(ver), "%s%s", feature_info[i].name, feature_info[i].version);
					
					//verify the signature file
					if(verify_download_file(path, ver) == ASD_SUCCESS)
					{
						if(load_file_in_shm(path, shm_map->key, 1) == ASD_SUCCESS)
						{
							ASD_DBG("[%s] Load file (%s) in the share memory\n", __FUNCTION__, path);
						}
						else
						{
							ASD_DBG("[%s] Cannot load file (%s) in share memory.\n", __FUNCTION__, path);
							ret = ASD_FAIL;
						}
					}
					else
					{
						ASD_DBG("[%s] Signature file (%s) is invalid\n", __FUNCTION__, path);
						ret = ASD_FAIL;
					}
				}
				else
				{
					ASD_DBG("[%s] Cannot find feature(%s) in shm define.\n", __FUNCTION__, feature_info[i].name);
					ret = ASD_FAIL;
				}
			}
		}
		else
		{
			ASD_DBG("[%s] Load version file fail\n", __FUNCTION__);
			ret = ASD_FAIL;
		}
	}
	else
	{
		ASD_DBG("[%s] version file is invalid!\n", __FUNCTION__);
		ret = ASD_FAIL;
	}	
	return ret;
}


char *get_buf_from_shm(const unsigned int key)
{
	char *addr, *buf = NULL;
	unsigned int size = _find_size_by_key(key);
	int shmid;

	if(!size)
		return NULL;

	shmid = shmget(key, size, 0666);
	if(shmid == -1)
		return NULL;

	addr = shmat(shmid, NULL, 0);
	if(addr)
	{
		buf = calloc(size + 1, 1);
		if(!buf)
		{
			shmdt(addr);
			return NULL;
		}
		memcpy(buf, addr, size);
		shmdt(addr);
	}
	return buf;
}

char *get_buf_from_shm_by_name(const char *name)
{
	unsigned int key;
	if(!name)
		return NULL;
	
	key = find_shm_key_by_name(name);

	return get_buf_from_shm(key);	
}

int set_buf_to_shm(const unsigned int key, const char *buf, const size_t size)
{
	char *addr;
	unsigned int shm_sz = _find_size_by_key(key);
	int shmid;

	if(!shm_sz || shm_sz < size || !buf)
		return ASD_FAIL;

	shmid = shmget(key, shm_sz, 0666);
	if(shmid == -1)
		return ASD_FAIL;

	addr = shmat(shmid, NULL, 0);
	if(addr)
	{
		memset(addr, 0, shm_sz);
		memcpy(addr, buf, size);
		shmdt(addr);
		return ASD_SUCCESS;
	}
	return ASD_FAIL;
}

int set_buf_to_shm_by_name(const char *name, const char *buf, const size_t size)
{
	unsigned int key;
	if(!name || !buf)
		return ASD_FAIL;
	
	key = find_shm_key_by_name(name);

	return set_buf_to_shm(key, buf, size);
}
#endif	//SUPPORT_ASD_SHM
