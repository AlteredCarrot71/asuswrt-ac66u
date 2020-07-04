#ifndef __ASD_SHM_H__
#define __ASD_SHM_H__

#define ASD_SHM_KEY_INVALID		0
#define ASD_SHM_KEY_PUBLIC_KEY		518795
#define ASD_SHM_KEY_VERSION		518796
#define ASD_SHM_KEY_BLKDNS			518797
#define ASD_SHM_KEY_BLKIP			518798
#define ASD_SHM_KEY_BLKFILE			518799

#define ASD_SHM_SIZE_PUBLIC_KEY	1024		// 1k
#define ASD_SHM_SIZE_VERSION		1024		// 1k
#define ASD_SHM_SIZE_BLKDNS		20*1024		// 20k
#define ASD_SHM_SIZE_BLKIP			10*1024		// 10k
#define ASD_SHM_SIZE_BLKFILE		10*1024		// 10k

typedef struct _ASD_SHM_MAP
{
	unsigned int key;
	unsigned int size;
	const char *name;
}ASD_SHM_MAP;

const unsigned int find_shm_key_by_name(const char *name);
int load_file_in_shm(const char *file, const int key, const int with_sig);
int is_shm_created(const int key);
int init_shm();
char *get_buf_from_shm(const unsigned int key);
char *get_buf_from_shm_by_name(const char *name);

#endif
