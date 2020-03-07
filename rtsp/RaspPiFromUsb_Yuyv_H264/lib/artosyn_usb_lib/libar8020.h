#ifndef __DEMO_LIB__
#define __DEMO_LIB__


#include <sys/stat.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <malloc.h>
#include <pthread.h>


#ifdef __cplusplus
extern "C"
{
#endif

    /*  IS_STREAM
     *  1 : stream mode
     *  0 : pkg mode
     */
    #define IS_STREAM   1
    #define MAX_PKG_LEN 0x100000
    #define CMD_BUSY 1
    
    typedef void * PORT;
    
    typedef struct UPGRADE{
        
        unsigned char flag;
        unsigned char H_id;
        unsigned char L_id;
        unsigned char state1;
        unsigned char state2;
    
    }UPGRADE;
    
    typedef struct PARSE_PKG{
            
    	unsigned char head[8];
    	unsigned int head_len;
    	
    	char *usr_data;
    	int  usr_data_len;
    
    }PARSE_PKG;

    extern pthread_mutex_t port0_mutex;
    extern int Cmd_Port_Open(PORT *port,char *param);
    extern int Video_Port_Open(PORT *port,char *param);
    extern int Audio_Port_Open(PORT *port,char *param);
    extern int Pkg_Open(PORT *port,char *param);

    /* switch to cmd bypass mode
     */
    int To_Cmd_ByPass_Mode(PORT port);
    
    /* Cmd_Bypass_Rec:
     * allow usr to rec cmd ack frome mode directory
     */
    int Cmd_Bypass_Rec(PORT port,char *data,int count);
    
    /* Cmd_Bypass_Send:
     * allow usr to send cmd to mode directory
     */
    int Cmd_Bypass_Send(PORT port,char *data,int count);

    extern int Video_Port_Send(PORT port,char *data,int count);
    extern int Video_Port_Rec(PORT port,char *data,int count);
    
    extern int Audio_Port_Send(PORT port,char *data,int count);
    extern int Audio_Port_Rec(PORT port,char *data,int count);
    extern int Pkg_Send(PORT port,char *data,int count);
    extern int Pkg_Rec(PORT port,char *data,int count);
    
    extern int Cmd_Port_Close(PORT port);
    
    extern int Video_Port_Close(PORT port);
    extern int Audio_Port_Close(PORT port);
    extern int Pkg_Close(PORT port);

    int Usb_Init(void);

#ifdef __cplusplus
}
#endif

#endif

