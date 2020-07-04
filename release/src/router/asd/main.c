#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <shared.h>
#include <signal.h>

#include "signature.h"
#include "feature_def.h"
#include "security_daemon.h"

#define ASD_PIDFILE "/var/run/asd.pid"

int stop = 0, check_server = 0;

/*******************************************************************
* NAME: init
* AUTHOR: Andy Chiu
* CREATE DATE: 2019/12/18
* DESCRIPTION: init function to handle the signature files.
* INPUT: None
* OUTPUT: None
* RETURN: ASD_SUCCESS or ASD_FAIL
* NOTE:
*******************************************************************/
int init()
{
    char buf[256];

    //create sd folder
    if (!check_if_dir_exist(local_asd_dir[0]))
    {
        ASD_DBG("[%s] Create asd folder.\n", __FUNCTION__);
        mkdir(local_asd_dir[0], 0744);
    }

    //verify all files.
    if(are_all_sig_file_valid() == ASD_FAIL)
    {
        //remove all invalid files in the directory
        ASD_DBG("[%s] Remove all invalid files\n", __FUNCTION__);
        snprintf(buf, sizeof(buf), "rm -rf %s/*", local_asd_dir[0]);
        system(buf);
    }	
    else	//load signature files
    {
        ASD_DBG("[%s] Load exist signature files.\n", __FUNCTION__);
        update_signature_in_all_feature();
    }

    return ASD_SUCCESS;
}

/*******************************************************************
* NAME: write_pid_file
* AUTHOR: Andy Chiu
* CREATE DATE: 2019/12/18
* DESCRIPTION: write the pid file on /var/run 
* INPUT: None 
* OUTPUT: None 
* RETURN: None
* NOTE:
*******************************************************************/
void write_pid_file(void)
{
    int pid_file = 0;
    char pidbuf[8] = {0};
    int pidbuflen = 0;

    pid_file = open(ASD_PIDFILE, O_CREAT | O_RDWR, 0666);
    if(pid_file != -1)
    {
        pidbuflen = snprintf(pidbuf, sizeof(pidbuf), "%d", getpid());
        write(pid_file, pidbuf, pidbuflen);
        close(pid_file);
    }
    else
    {
        ASD_DBG("[%s]Cannot create %s.\n", __FUNCTION__, ASD_PIDFILE);
        exit(0);
    }
}

/*******************************************************************
* NAME: interrupt_handler
* AUTHOR: Andy Chiu
* CREATE DATE: 2019/12/18
* DESCRIPTION: The callback function to handle signal.
* INPUT: None 
* OUTPUT: None 
* RETURN: None 
* NOTE:
*******************************************************************/
void interrupt_handler(int sig)
{
    if(sig == SIGUSR1)
    {
        //check signature file version on the server.
        check_server = 1;
    }
}

/*******************************************************************
* NAME: main
* AUTHOR: Andy Chiu
* CREATE DATE: 2019/12/18
* DESCRIPTION: main function
* INPUT:  
* OUTPUT:  None
* RETURN: ASD_SUCCESS or ASD_FAIL  
* NOTE:
*******************************************************************/
int main(int argc, char **argv)
{
    signal(SIGUSR1, interrupt_handler);

    write_pid_file();

    //init variable
    feature_list_init();

    //init feature
    init();	

    while(!stop)
    {
        if(check_server)
        {
            //check and download the new version of signature on the server.
            check_version_from_server();
            check_server = 0;			
        }
        else
        {
            handle_signature();
        }
        do_feature_period();
        sleep(10);
    }
    return 0;
}

