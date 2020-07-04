#ifndef __SECURITY_DAEMON_H__
#define __SECURITY_DAEMON_H__

#include "protect_name.h"
#include "feature_def.h"
#include "utility.h"

#define ASD_DBG(fmt, args...) \
	do { \
		asdprint(fmt, ##args); \
	} while(0)


#define ASD_SIG_LEN	256

#define ASD_SUCCESS 1
#define ASD_FAIL	0

//If enable ASD_DEBUG, asd won't check signature and decode the signature file in /jffs/asd.
//You can test your feature without upload the signature files. Just need to put them in /jffs/asd
//#define ASD_DEBUG    1

#endif
