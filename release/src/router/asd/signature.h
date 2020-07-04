#ifndef __SIGNATURE_H__
#define __SIGNATURE_H__

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
int are_all_sig_file_valid();

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
int check_version_from_server();

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
int handle_signature();

#endif
