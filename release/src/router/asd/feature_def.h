#ifndef __FEATURE_DEF__
#define __FEATURE_DEF__

#define ASD_MAX_FEATURE_NUM	3
#define ASD_SIG_VER_LEN		12

typedef struct _feature_define
{
	const char *name;	//feature name
	unsigned int period;	//period time to call the period_func
	long last_period_call;	//last time to call period_func
	int (*action)();		//call this function after update signature
	int (*period_func)(const long now);		//call this function periodically
	char sig_ver[ASD_SIG_VER_LEN];	//the version of the signature file
	char *sig_buf;	//the content of the signature file	
}FEATURE_DEFINE;

//The index for get_feature_by_index()
enum{
	NEXT_FEATURE = -1,
	FIRST_FEATURE = 0
};

typedef int (*feature_init)(void);

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
int feature_list_init();

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
int register_feature(FEATURE_DEFINE *feature);

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
FEATURE_DEFINE* find_feature(const char *name);

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
FEATURE_DEFINE *get_feature_by_index(const int index);

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
int do_feature_period();

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
int update_signature_in_feature(const char *name, const char *version);

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
int update_signature_in_all_feature();

#endif
