#ifndef __UTILITY_H__
#define __UTILITY_H__

#include "security_daemon.h"

#define SAFE_FREE(x) if(x) {free(x); x=NULL;} 

#define ASD_MAX_NAME_LEN		64
#define ASD_MAX_VERSION_LEN	32

typedef struct _FEATURE_INFO
{
	char name[ASD_MAX_NAME_LEN];
	char version[ASD_MAX_VERSION_LEN];
}FEATURE_INFO;

enum{
	ASD_DATA_FROM_FILE,
	ASD_DATA_FROM_BK_FILE,
};


extern int blockfile_rule_hit[1024];
extern int chknvram_rule_hit[1024];

void reset_rule_hit();

#if 0
typedef struct _CONTENT_BY_LINE
{
	int num;
	unsigned char *checked;
	char **line;
}CONTENT_BY_LINE;

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
void dump_content(CONTENT_BY_LINE *content);

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
void free_content(CONTENT_BY_LINE *content);

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
int read_file_in_content(const char *file_path,  const char *filter, CONTENT_BY_LINE *content);
#endif

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
void asdprint(const char * format, ...);

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
int verify_file(const char *file, const char *verline, const int file_enc);

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
int get_feature_list_from_version(const int from, FEATURE_INFO *feature_info, const size_t size);

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
char *read_file(const char *file, const int check_sig, const int file_enc);

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
int encrypt_file(const char *src_file, const char *dst_file, const int with_sig);
#endif
