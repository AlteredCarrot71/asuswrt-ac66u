#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <curl/curl.h>
#include <openssl/md5.h>
#include <shared.h>
#include <shutils.h>
#include <time.h>

#include <shared.h>
#include <libasc.h>

#include "security_daemon.h"
#include "feature_def.h"
#include "utility.h"

#define MAX_RETRY  3
#define CHECK_SIGNATURE_PERIOD		86400		//24 hours

/*******************************************************************
* NAME: _download_file
* AUTHOR: Andy Chiu
* CREATE DATE: 2019/12/18
* DESCRIPTION: download the file from server.
* INPUT:  file_name: string, the file name on the server. 
*         local_file_path: string.the local file path to store the download file.
* OUTPUT: None 
* RETURN:  ASD_SUCCESS or ASD_FAIL
* NOTE:
*******************************************************************/
static int _download_file(const char* file_name, const char *local_file_path)
{
	if(!file_name || !local_file_path)
		return ASD_FAIL;
	
	nvram_set("sd_feature", file_name);
	return (curl_download_file(SECURITY_DAEMON, dl_path_file_name[0], local_file_path) == LIBASC_SUCCESS)? ASD_SUCCESS: ASD_FAIL;	
}

/*******************************************************************
* NAME: _download_and_verify_file
* AUTHOR: Andy Chiu
* CREATE DATE: 2019/12/18
* DESCRIPTION: download the file on server and verify it.
* INPUT:  file_name: string, the file name on the server.
*         local_file_path: string.the local file path to store the download file.
*         check_verline: bool number. If 1, check the first line in the file. It must be version.
* OUTPUT:  None
* RETURN:  ASD_SUCCESS or ASD_FAIL
* NOTE:
*******************************************************************/
static int _download_and_verify_file(const char* file_name, const char *local_file_path, const int check_verline)
{
	int i;
	char cmd[256], enc_path[256];

	if(!file_name || !local_file_path)
		return ASD_FAIL;


	//download and verify file
	for(i = 0; i < MAX_RETRY; ++i)
	{
		if(_download_file(file_name, local_file_path) == ASD_SUCCESS &&
			verify_file(local_file_path, check_verline? file_name: NULL, 0) == ASD_SUCCESS)
		{
			//encrypt file
			snprintf(enc_path, sizeof(enc_path), "%s_enc", local_file_path);
			if(encrypt_file(local_file_path, enc_path, 1) == ASD_SUCCESS)
			{
				unlink(local_file_path);
				snprintf(cmd, sizeof(cmd), "mv %s %s", enc_path, local_file_path);
				system(cmd);
				break;
			}
		}
	}
	if(i >= MAX_RETRY)
	{
		ASD_DBG("[%s] Download file (%s) fail!\n", __FUNCTION__, file_name);
		return ASD_FAIL;
	}
	return ASD_SUCCESS;
}

/*******************************************************************
* NAME: _check_and_dl_file
* AUTHOR: Andy Chiu
* CREATE DATE: 2019/12/18
* DESCRIPTION: Verify the local file first. If it's invalid, download it.
* INPUT:  feature: string, name of feature.
*         path: string, the full path of local direction to store the file.
*         check_verline: bool number, if 1, check the first line in the file. It must be the version of it.
* OUTPUT:  None
* RETURN:  ASD_SUCCESS or ASD_FAIL
* NOTE:
*******************************************************************/
static int _check_and_dl_file(const char *feature, const char *path, const int check_verline)
{
	int i;
	char tmp[256], enc_path[256];
	if(!feature || !path)
		return ASD_FAIL;

	//check file and redownload it if it's invalid
	if(verify_file(path, check_verline? feature: NULL, 1) == ASD_FAIL)
	{
		if(!internet_ready())
		{
			unlink(path);	//remove invalid file
			return ASD_FAIL;
		}
		else
		{
			return _download_and_verify_file(feature, path, check_verline);
		}
	}
	return ASD_SUCCESS;
}

/*******************************************************************
* NAME: _check_ver_and_sig_file
* AUTHOR: Andy Chiu
* CREATE DATE: 2019/12/18
* DESCRIPTION: Check the sig_buf abd version in feature definitin with the local version file and update it it there is a new version or the sig_buf is NULL.
* INPUT:  None
* OUTPUT:  None
* RETURN:  ASD_SUCCESS or ASD_FAIL
* NOTE:
*******************************************************************/
static int _check_ver_and_sig_file()
{
	FEATURE_INFO feature_info[ASD_MAX_FEATURE_NUM];
	int cnt, i, ret = ASD_SUCCESS;
	char path[256], sd_feature[64];
	FEATURE_DEFINE	*fd;
	
	//check version file and redownload it if it's invalid
	if(_check_and_dl_file(version_name[0], local_ver_path[0], 0) == ASD_FAIL)
	{
		ASD_DBG("[%s] Version file is invalid!\n", __FUNCTION__);
		unlink(local_ver_path[0]);
		return ASD_FAIL;
	}
	
	//check feature file
	cnt = get_feature_list_from_version(ASD_DATA_FROM_FILE, feature_info, ASD_MAX_FEATURE_NUM);
	for(i = 0; i < cnt; ++i)
	{
		fd = find_feature(feature_info[i].name);
		if(fd)
		{
			//If the feature did not load signature or the version in the version file is newer than it in the feature definition,
			//download the signature file and update into feature definition.
			if(!fd->sig_buf || strcmp(feature_info[i].version, fd->sig_ver) > 0)
			{
				snprintf(sd_feature, sizeof(sd_feature), "%s%s", feature_info[i].name, feature_info[i].version);
				snprintf(path, sizeof(path), "%s/%s%s", local_asd_dir[0], feature_info[i].name, feature_info[i].version);
				if(_check_and_dl_file(sd_feature, path, 1) == ASD_SUCCESS)
				{
					if(update_signature_in_feature(feature_info[i].name, feature_info[i].version) == ASD_FAIL)
					{
						ASD_DBG("[%s] update sig file in fetaure FAIL!\n", __FUNCTION__);
						ret = ASD_FAIL;
					}
				}
				else
					ret = ASD_FAIL;
			}
		}
	}
	return ret;
}

/*******************************************************************
* NAME: are_all_sig_file_valid
* AUTHOR: Andy Chiu
* CREATE DATE: 2019/12/18
* DESCRIPTION: verify all local version file and signature files.
* INPUT:  None
* OUTPUT:  None
* RETURN:  ASD_SUCCESS or ASD_FAIL
* NOTE:
*******************************************************************/
int are_all_sig_file_valid()
{
	FEATURE_INFO feature_info[ASD_MAX_FEATURE_NUM];
	int cnt, i;
	char path[256], ver[64];
#ifdef ASD_DEBUG
        int file_enc = 0;
#else
        int file_enc = 1;
#endif

	if(verify_file(local_ver_path[0], NULL, file_enc) == ASD_FAIL)
	{
		ASD_DBG("[%s] Local version file is invalid!\n", __FUNCTION__);
		return ASD_FAIL;
	}

	cnt = get_feature_list_from_version(ASD_DATA_FROM_FILE, feature_info, ASD_MAX_FEATURE_NUM);
	for(i = 0; i < cnt; ++i)
	{
		if(find_feature(feature_info[i].name))
		{
			snprintf(path, sizeof(path), "%s/%s%s", local_asd_dir[0], feature_info[i].name, feature_info[i].version);
			snprintf(ver, sizeof(ver), "%s%s", feature_info[i].name, feature_info[i].version);
			if(verify_file(path, ver, file_enc) == ASD_FAIL)
			{
				ASD_DBG("[%s] signature file(%s) is invalid.\n", __FUNCTION__, path);
				return ASD_FAIL;
			}
		}
		else
			ASD_DBG("[%s] feature(%s) not support!\n", __FUNCTION__, feature_info[i].name);
	}
	return ASD_SUCCESS;
}

/*******************************************************************
* NAME: check_version_from_server
* AUTHOR: Andy Chiu
* CREATE DATE: 2019/12/18
* DESCRIPTION: download the version from the server and check whether there is new version. 
* INPUT:  None
* OUTPUT:  None
* RETURN:  ASD_SUCCESS or ASD_FAIL
* NOTE:
*******************************************************************/
int check_version_from_server()
{
	FEATURE_INFO f_info_file[ASD_MAX_FEATURE_NUM];
	int i, j, ret = ASD_SUCCESS, flag = 0;
	int cnt_shm, cnt_file;
	char path[256], feature[64], sd_feature[64];
	time_t now;
	FEATURE_DEFINE	*fd;

	time(&now);
	ASD_DBG("[%s] Check server at %s.", __FUNCTION__, ctime(&now));
	
	//download version file and store it in the backup path
	if(_download_and_verify_file(version_name[0], local_ver_bk_path[0], 0) == ASD_SUCCESS)
	{
		//compare version file and the version in the feature list.
		cnt_file = get_feature_list_from_version(ASD_DATA_FROM_BK_FILE, f_info_file, ASD_MAX_FEATURE_NUM);
		
		//compare feature version
		for(i = 0; i < cnt_file; ++i)
        {
		    fd = find_feature(f_info_file[i].name);
			if(fd)
			{
				//If the feature did not load signature or the version in the version file is newer than it in the feature definition,
				//download the signature file and update into feature definition.
				if(!fd->sig_buf || strcmp(f_info_file[i].version, fd->sig_ver) > 0)
				{
					snprintf(sd_feature, sizeof(sd_feature), "%s%s", f_info_file[i].name, f_info_file[i].version);
					snprintf(path, sizeof(path), "%s/%s%s", local_asd_dir[0], f_info_file[i].name, f_info_file[i].version);
					if(_check_and_dl_file(sd_feature, path, 1) == ASD_SUCCESS)
					{
						if(update_signature_in_feature(f_info_file[i].name, f_info_file[i].version) == ASD_FAIL)
						{
							ASD_DBG("[%s]update sig file in feture FAIL!\n", __FUNCTION__);
                            ret = ASD_FAIL;
						}
                        else
                            flag = 1;
					}
					else
						ret = ASD_FAIL;
				}
            }
        }		
        if(flag == 1)
		{
			unlink(local_ver_path[0]);
			eval("mv", local_ver_bk_path[0], local_ver_path[0]);
			ASD_DBG("[%s]update version file\n", __FUNCTION__);
		}
		unlink(local_ver_bk_path[0]);
	}
    else
        ret = ASD_FAIL;
	return ret;
}

/*******************************************************************
* NAME: handle_signature
* AUTHOR: Andy Chiu
* CREATE DATE: 2019/12/18
* DESCRIPTION: check the version and the signature related variable in the feature list.
* INPUT:  None
* OUTPUT:  None
* RETURN:  ASD_SUCCESS or ASD_FAIL
* NOTE:
*******************************************************************/
int handle_signature()
{
	long now = uptime();
	static long last_check = 0;

	if(now - last_check < CHECK_SIGNATURE_PERIOD)
		return ASD_SUCCESS;
	else
		last_check = now;

	_check_ver_and_sig_file();

	return ASD_SUCCESS;
}


