
#include "libar8020.h"

#ifndef NULL
#define NULL ((void *)0)
#endif


#define UPGRADE_START           _IOWR('s',130,long)
#define CMD_BYPASS_MODE        _IOWR('s',138,long)
#define CMD_NORMAL_MODE         _IOWR('s',139,long)
#define TX_PARSE_MODE          _IOWR('s',140,long)

#define MAX_TRANSFER 2048

pthread_mutex_t port0_mutex;
pthread_mutex_t port1_mutex;

#define min(a,b)(a<b?a:b)

typedef struct  
{  
    unsigned int count[2];  
    unsigned int state[4];  
    unsigned char buffer[64];     
}MD5_CTX;


    
int Cmd_Port_Open(PORT *port,char *param)
{
    int port0;
    
    port0 = open("/dev/artosyn_port0", O_RDWR, S_IRUSR | S_IWUSR);
    if(port0 < 0)
    {
        return port0;
    }
    
    *port = (PORT)port0;
    
    return 0;

}

int Video_Port_Open(PORT *port,char *param)
{
    int port1;
    unsigned int *p;
    
    port1 = open("/dev/artosyn_port1", O_RDWR, S_IRUSR | S_IWUSR);
    
    if(port1 < 0)
        return -1;
    
    *port = (PORT)port1;
    
    return 0;
}

int Audio_Port_Open(PORT *port,char *param)
{
    int port1;
    unsigned int *p;
    
    port1 = open("/dev/artosyn_port2", O_RDWR, S_IRUSR | S_IWUSR);
    
    if(port1 < 0)
        return -1;
    
    *port = (PORT)port1;
    
    return 0;
}

int Pkg_Open(PORT *port,char *param)
{
    int port1;
    unsigned int *p;
    
    port1 = open("/dev/artosyn_port1", O_RDWR, S_IRUSR | S_IWUSR);
    
    if(port1 < 0)
        return -1;
    
    *port = (PORT)port1;
    
    return 0;
}

int To_Cmd_ByPass_Mode(PORT port)
{
    int ret;

    ret = ioctl((int)port,CMD_BYPASS_MODE,0);
    return ret;
}

int Cmd_Bypass_Rec(PORT port,char *data,int count)
{
    int ret;

    if(port == NULL || data == NULL)
        return -1;
    ret = read((int)port,data,count);

    return ret;
}

int Cmd_Bypass_Send(PORT port,char *data,int count)
{
    int ret;

    if(port == NULL || data == NULL)
        return -1;
    
    ret = write((int)port,data,count);

    return ret;
}



unsigned char Get_Crc8(unsigned char *ptr,unsigned int len)
{
    unsigned char crc;
    unsigned char i;
    crc=0;
    while(len--)
    {
        crc^=*ptr++;
        for(i=0;i<8;i++)
        {
            if(crc&0x01)crc=(crc>>1)^0x8C;
            else crc >>= 1;
        }
    }
    return crc;
}
  
static int Get_File_Size(const char* file) 
{  
    struct stat tbuf;  
    stat(file, &tbuf);  
    return tbuf.st_size;  
} 

//protocol list
static int Cmd_Ret_Ok(PORT port,unsigned char *buffer,int timeout)
{
    int i;
    int ret;
    char state = 0;
    unsigned char pkg_ret[512];
    for(i = 0;i < timeout;i ++)
    {
        ret = read((int)port,pkg_ret,1);
        if(ret > 0)
        {
            switch(state)
            {
                case 0:
                    if(pkg_ret[0] == buffer[state])
                        state ++;
                    else
                        state = 0;
                    break;
                case 1:
                    if(pkg_ret[0] == buffer[state])
                        state ++;
                    else
                        state = 0;
                    break;
                case 2:
                    if(pkg_ret[0] == buffer[state])
                        state ++;
                    else
                        state = 0;
                    break;
                case 3:
                    if(pkg_ret[0] == buffer[state])
                        state ++;
                    else
                        state = 0;
                    break;
                default:
                    state = 0;
                    break;
            }
            if(state == 4)
                return 0;
        }
        else if(ret == 0)
            usleep(1000);
        else
        {
            printf("usb connect err\n");
            return -1;
        }
    }
    
    if(i >= timeout)
    {
        printf("timeout !!!\n");
        return 1;
    }
        
}

int Cmd_Upgrade_V1(PORT port,int dev,char *upgrade_file)
{
    int i,j;
    int fsize;
    int fd;
    int ret;
    int ret2;
    int id;
    unsigned char state = 0;
    unsigned char buffer[512];
    unsigned char pkg_ret[512];

//upgrade send data
    fsize = Get_File_Size(upgrade_file);
    printf("get file size: %d\n",fsize);

    fd = open(upgrade_file, O_RDWR, S_IRUSR | S_IWUSR);
    if(fd < 0)
    {
        printf("upgrade file not exist\n");
        return -1;
    }
    
    buffer[0] = 0x01;
    buffer[1] = 0x01;
    buffer[2] = 0x03;
    buffer[3] = (unsigned char)(fsize >> 16);
    buffer[4] = (unsigned char)(fsize >> 8);
    buffer[5] = (unsigned char)fsize;

    if(write((int)port,buffer,6) != 6)
    {
        printf("usb send err\n");
        return -1;
    }
    
    pkg_ret[0] = 0x01;
    pkg_ret[1] = 0x01;
    pkg_ret[2] = 0x00;
    pkg_ret[3] = 0x00;
    if(Cmd_Ret_Ok(port,pkg_ret,200) < 0)
        return -1;

    buffer[0] = 0x01;
    buffer[1] = 0x02;

    id = 0;
    //data send
    while(fsize > 0)
    {
        if(fsize > 506)
        {
            ret = read(fd,&buffer[6],506);
            if(ret > 0)
            {
                buffer[2] = (unsigned char)(ret >> 8);
                buffer[3] = (unsigned char)ret;
                
                buffer[4] = (unsigned char)(id >> 8);
                buffer[5] = (unsigned char)id;
                
                if(write((int)port,buffer,ret + 6) != (ret + 6))
                {
                    printf("usb send err\n");
                    return -1;
                }
                
                //wait for ack
                pkg_ret[0] = 0x01;
                pkg_ret[1] = 0x02;
                pkg_ret[2] = 0x00;
                pkg_ret[3] = 0x00;
                ret2 = Cmd_Ret_Ok(port,pkg_ret,200);
                if(ret2 < 0)
                    return -1;
                else if(ret2 == 1)
                    continue;
                else if(ret2 == 0)
                {
                    fsize -= ret;
                    id ++;
                }  
            }     
        }
        else //last pkg
        {
            buffer[1] = 0x00;
            
            ret = read(fd,&buffer[6],fsize);
            if(ret > 0)
            {
                if(ret != fsize)
                {
                    printf("last pkg read err\n");
                    return -1;
                }
                
                buffer[2] = (unsigned char)(ret >> 8);
                buffer[3] = (unsigned char)ret;
                
                buffer[4] = (unsigned char)(id >> 8);
                buffer[5] = (unsigned char)id;
                
                if(write((int)port,buffer,ret + 6) != (ret + 6))
                {
                    printf("usb send err\n");
                    return -1;
                }
                
                //wait for ack
                pkg_ret[0] = 0x01;
                pkg_ret[1] = 0x03;
                pkg_ret[2] = 0x00;
                pkg_ret[3] = 0x00;

                ret2 = Cmd_Ret_Ok(port,pkg_ret,30000);
                if(ret2 < 0)
                    return -1;
                else if(ret2 == 1)
                {
                    printf("upgrade check err\n");
                    return -1;
                }                    
                else if(ret2 == 0)
                {
                    printf("upgrade success\n");
                    return 0;
                }
            }
        }
    }
    
    return ret;

}

int Cmd_Upgrade_V2(PORT port,int dev,char *upgrade_file)
{
    int i,j;
    int fsize;
    int fsize2 = 0;
    int fd;
    int ret;

    unsigned char buffer[512];
    unsigned char pkg_ret[512];
    int totalframe;
    int nCurrentFrame = 0;
    int length;
    unsigned int sum;
    int wait_time;
    int need_retry = 0;
  
    while(read((int)port,pkg_ret,512) > 0);

//upgrade send data
    fsize = Get_File_Size(upgrade_file);
    printf("get file size: %d\n",fsize);

    totalframe = (fsize + 495) / 496;

    fd = open(upgrade_file, O_RDWR, S_IRUSR | S_IWUSR);
    if(fd < 0)
    {
        printf("upgrade file not exist\n");
        return -1;
    }

    while(1)
    {
        if(need_retry == 0)
        {
            length = read(fd,buffer + 16,496);
            if (length <= 0)
            {
                close(fd);
                return -1;
            }
            //fsize2 += (unsigned int)length;
            length += 6; //data length
    
            buffer[0] = 0xff;
            buffer[1] = 0x5a;
            buffer[2] = 0x01;
            buffer[3] = 0x00;
            buffer[4] = 0x01;
            buffer[5] = 0x00;
            buffer[6] = (char)length;
            buffer[7] = (char)(length >> 8);
    
            buffer[10] = 0;//本地升级
            buffer[11] = 0;
            buffer[12] = (char)nCurrentFrame;
            buffer[13] = (char)(nCurrentFrame >> 8);
            buffer[14] = (char)totalframe;                        
            buffer[15] = (char)(totalframe >> 8);
    
            //add check for frame
            for(i = 0,sum = 0;i < length;i ++)
            {
                sum += (unsigned char)buffer[i + 10];
            }
            buffer[8] = (char)sum;
            buffer[9] = (char)(sum >> 8);
        }
        ret = write((int)port,buffer,length + 10);

        if(nCurrentFrame < (totalframe - 1))
            wait_time = 200;
        else
            wait_time = 2000;
            
        //等待回应
        for(j = 0;j < wait_time;j ++)
        {
            usleep(10000);
            ret = read((int)port,pkg_ret,512);
            if(ret > 0)
            {
                //pkg okg
                if(pkg_ret[0] == 0xff && pkg_ret[1] == 0x5a 
                && pkg_ret[2] == 0x01 && pkg_ret[3] == 0x00 && pkg_ret[10] == 0x01)
                {
                    nCurrentFrame++;
                    if(nCurrentFrame == totalframe)
                    {
                        printf("progress : %d / %d\n",nCurrentFrame,totalframe);
                        printf("========================================================\n");
                        printf("\t\tupgrade successed\n");
                        printf("========================================================\n");
                        return 0;
                    }
                    else
                       break;
                }
                //pkg failed
                else if(pkg_ret[0] == 0xff && pkg_ret[1] == 0x5a 
                && pkg_ret[2] == 0x01 && pkg_ret[3] == 0x00 && pkg_ret[10] == 0x00)
                {
                    //last pkg failed
                    if(wait_time == 2000)
                    {
                        printf("========================================================\n");
                        printf("upgrade failed ,Please restart the module and update it\n");
                        printf("========================================================\n");
                        return -1;
                    }
                    //common pkg failed
                    else
                    {
                        j = wait_time; 
                        break;
                    }
                }
                //pkg no ack
                else
                    continue;
            }
        }

        if(j == wait_time)
        {
            need_retry ++;
            if(need_retry > 5)
            {
                printf("========================================================\n");
                printf("upgrade failed ,Please restart the module and update it\n");
                printf("========================================================\n");
                return -1;
            }
        }   
        else
            need_retry = 0;
        
        printf("progress : %d / %d\n",nCurrentFrame,totalframe);

    }

    return 0;

}


//md5 handler

#define F(x,y,z) ((x & y) | (~x & z))  
#define G(x,y,z) ((x & z) | (y & ~z))  
#define H(x,y,z) (x^y^z)  
#define I(x,y,z) (y ^ (x | ~z))  
#define ROTATE_LEFT(x,n) ((x << n) | (x >> (32-n)))  
#define FF(a,b,c,d,x,s,ac) \
          { \
          a += F(b,c,d) + x + ac; \
          a = ROTATE_LEFT(a,s); \
          a += b; \
          }  
          
#define GG(a,b,c,d,x,s,ac) \
          { \
          a += G(b,c,d) + x + ac; \
          a = ROTATE_LEFT(a,s); \
          a += b; \
          }  
          
#define HH(a,b,c,d,x,s,ac) \
          { \
          a += H(b,c,d) + x + ac; \
          a = ROTATE_LEFT(a,s); \
          a += b; \
          }  
          
#define II(a,b,c,d,x,s,ac) \
          { \
          a += I(b,c,d) + x + ac; \
          a = ROTATE_LEFT(a,s); \
          a += b; \
          }   
          
unsigned char PADDING[] = {
    0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
          
void MD5Init(MD5_CTX *context)  
{  
     context->count[0] = 0;  
     context->count[1] = 0;  
     context->state[0] = 0x67452301;  
     context->state[1] = 0xEFCDAB89;  
     context->state[2] = 0x98BADCFE;  
     context->state[3] = 0x10325476;  
}  

void MD5Decode(unsigned int *output,unsigned char *input,unsigned int len)  
{  
     unsigned int i = 0,j = 0;  
     while(j < len)  
     {  
        output[i] = (input[j]) |  
            (input[j+1] << 8)  |  
            (input[j+2] << 16) |  
            (input[j+3] << 24);  
        i++;  
        j+=4;   
     }  
}  

void MD5Transform(unsigned int state[4],unsigned char block[64])  
{  
    unsigned int a = state[0];  
    unsigned int b = state[1];  
    unsigned int c = state[2];  
    unsigned int d = state[3];  
    unsigned int x[64];  
    MD5Decode(x,block,64);  
    FF(a, b, c, d, x[ 0], 7, 0xd76aa478); /* 1 */  
    FF(d, a, b, c, x[ 1], 12, 0xe8c7b756); /* 2 */  
    FF(c, d, a, b, x[ 2], 17, 0x242070db); /* 3 */  
    FF(b, c, d, a, x[ 3], 22, 0xc1bdceee); /* 4 */  
    FF(a, b, c, d, x[ 4], 7, 0xf57c0faf); /* 5 */  
    FF(d, a, b, c, x[ 5], 12, 0x4787c62a); /* 6 */  
    FF(c, d, a, b, x[ 6], 17, 0xa8304613); /* 7 */  
    FF(b, c, d, a, x[ 7], 22, 0xfd469501); /* 8 */  
    FF(a, b, c, d, x[ 8], 7, 0x698098d8); /* 9 */  
    FF(d, a, b, c, x[ 9], 12, 0x8b44f7af); /* 10 */  
    FF(c, d, a, b, x[10], 17, 0xffff5bb1); /* 11 */  
    FF(b, c, d, a, x[11], 22, 0x895cd7be); /* 12 */  
    FF(a, b, c, d, x[12], 7, 0x6b901122); /* 13 */  
    FF(d, a, b, c, x[13], 12, 0xfd987193); /* 14 */  
    FF(c, d, a, b, x[14], 17, 0xa679438e); /* 15 */  
    FF(b, c, d, a, x[15], 22, 0x49b40821); /* 16 */  
      
    /* Round 2 */  
    GG(a, b, c, d, x[ 1], 5, 0xf61e2562); /* 17 */  
    GG(d, a, b, c, x[ 6], 9, 0xc040b340); /* 18 */  
    GG(c, d, a, b, x[11], 14, 0x265e5a51); /* 19 */  
    GG(b, c, d, a, x[ 0], 20, 0xe9b6c7aa); /* 20 */  
    GG(a, b, c, d, x[ 5], 5, 0xd62f105d); /* 21 */  
    GG(d, a, b, c, x[10], 9,  0x2441453); /* 22 */  
    GG(c, d, a, b, x[15], 14, 0xd8a1e681); /* 23 */  
    GG(b, c, d, a, x[ 4], 20, 0xe7d3fbc8); /* 24 */  
    GG(a, b, c, d, x[ 9], 5, 0x21e1cde6); /* 25 */  
    GG(d, a, b, c, x[14], 9, 0xc33707d6); /* 26 */  
    GG(c, d, a, b, x[ 3], 14, 0xf4d50d87); /* 27 */  
    GG(b, c, d, a, x[ 8], 20, 0x455a14ed); /* 28 */  
    GG(a, b, c, d, x[13], 5, 0xa9e3e905); /* 29 */  
    GG(d, a, b, c, x[ 2], 9, 0xfcefa3f8); /* 30 */  
    GG(c, d, a, b, x[ 7], 14, 0x676f02d9); /* 31 */  
    GG(b, c, d, a, x[12], 20, 0x8d2a4c8a); /* 32 */  
      
    /* Round 3 */  
    HH(a, b, c, d, x[ 5], 4, 0xfffa3942); /* 33 */  
    HH(d, a, b, c, x[ 8], 11, 0x8771f681); /* 34 */  
    HH(c, d, a, b, x[11], 16, 0x6d9d6122); /* 35 */  
    HH(b, c, d, a, x[14], 23, 0xfde5380c); /* 36 */  
    HH(a, b, c, d, x[ 1], 4, 0xa4beea44); /* 37 */  
    HH(d, a, b, c, x[ 4], 11, 0x4bdecfa9); /* 38 */  
    HH(c, d, a, b, x[ 7], 16, 0xf6bb4b60); /* 39 */  
    HH(b, c, d, a, x[10], 23, 0xbebfbc70); /* 40 */  
    HH(a, b, c, d, x[13], 4, 0x289b7ec6); /* 41 */  
    HH(d, a, b, c, x[ 0], 11, 0xeaa127fa); /* 42 */  
    HH(c, d, a, b, x[ 3], 16, 0xd4ef3085); /* 43 */  
    HH(b, c, d, a, x[ 6], 23,  0x4881d05); /* 44 */  
    HH(a, b, c, d, x[ 9], 4, 0xd9d4d039); /* 45 */  
    HH(d, a, b, c, x[12], 11, 0xe6db99e5); /* 46 */  
    HH(c, d, a, b, x[15], 16, 0x1fa27cf8); /* 47 */  
    HH(b, c, d, a, x[ 2], 23, 0xc4ac5665); /* 48 */  
      
    /* Round 4 */  
    II(a, b, c, d, x[ 0], 6, 0xf4292244); /* 49 */  
    II(d, a, b, c, x[ 7], 10, 0x432aff97); /* 50 */  
    II(c, d, a, b, x[14], 15, 0xab9423a7); /* 51 */  
    II(b, c, d, a, x[ 5], 21, 0xfc93a039); /* 52 */  
    II(a, b, c, d, x[12], 6, 0x655b59c3); /* 53 */  
    II(d, a, b, c, x[ 3], 10, 0x8f0ccc92); /* 54 */  
    II(c, d, a, b, x[10], 15, 0xffeff47d); /* 55 */  
    II(b, c, d, a, x[ 1], 21, 0x85845dd1); /* 56 */  
    II(a, b, c, d, x[ 8], 6, 0x6fa87e4f); /* 57 */  
    II(d, a, b, c, x[15], 10, 0xfe2ce6e0); /* 58 */  
    II(c, d, a, b, x[ 6], 15, 0xa3014314); /* 59 */  
    II(b, c, d, a, x[13], 21, 0x4e0811a1); /* 60 */  
    II(a, b, c, d, x[ 4], 6, 0xf7537e82); /* 61 */  
    II(d, a, b, c, x[11], 10, 0xbd3af235); /* 62 */  
    II(c, d, a, b, x[ 2], 15, 0x2ad7d2bb); /* 63 */  
    II(b, c, d, a, x[ 9], 21, 0xeb86d391); /* 64 */  
    state[0] += a;  
    state[1] += b;  
    state[2] += c;  
    state[3] += d;  
}

void MD5Update(MD5_CTX *context,unsigned char *input,unsigned int inputlen)  
{  
    unsigned int i = 0,index = 0,partlen = 0;  
    index = (context->count[0] >> 3) & 0x3F;  
    partlen = 64 - index;  
    context->count[0] += inputlen << 3;  
    if(context->count[0] < (inputlen << 3))  
       context->count[1]++;  
    context->count[1] += inputlen >> 29;  
      
    if(inputlen >= partlen)  
    {  
       memcpy(&context->buffer[index],input,partlen);  
       MD5Transform(context->state,context->buffer);  
       for(i = partlen;i+64 <= inputlen;i+=64)  
           MD5Transform(context->state,&input[i]);  
       index = 0;          
    }    
    else  
    {  
        i = 0;  
    }  
    memcpy(&context->buffer[index],&input[i],inputlen-i);  
}  

void MD5Encode(unsigned char *output,unsigned int *input,unsigned int len)  
{  
    unsigned int i = 0,j = 0;  
    while(j < len)  
    {  
        output[j] = input[i] & 0xFF;    
        output[j+1] = (input[i] >> 8) & 0xFF;  
        output[j+2] = (input[i] >> 16) & 0xFF;  
        output[j+3] = (input[i] >> 24) & 0xFF;  
        i++;  
        j+=4;  
    }  
}  

void MD5Final(MD5_CTX *context,unsigned char digest[16])  
{  
    unsigned int index = 0,padlen = 0;  
    unsigned char bits[8];  
    index = (context->count[0] >> 3) & 0x3F;  
    padlen = (index < 56)?(56-index):(120-index);  
    MD5Encode(bits,context->count,8);  
    MD5Update(context,PADDING,padlen);  
    MD5Update(context,bits,8);  
    MD5Encode(digest,context->state,16);  
}  

typedef struct IMAGE_HEADER
{  
  char data[8];
  char version[4];
  char bootmode[2];
  char appsize[4];
  char MD5[16];
  char reserve[222];
}IMAGE_HEADER;

typedef struct UPGRADE_HEADER
{  
  char image_size[4];
  char EfuseMD5[16];
  char MD5[16];  
}UPGRADE_HEADER;

typedef struct FilePart
{  
  char* file_data;
  unsigned int size;
}FilePart; 

#define FULLFILE_BOOT_POS           0x0
#define FULLFILE_UPGRADE_POS        0x8000
#define FULLFILE_UPGRADEBAK_POS     0x18000
#define FULLFILE_APP_POS            0x28000
#define FULLFILE_APPBAK_POS         0x300000
#define IMAGE_HEADER_SIZE           256
#define UPGRADE_HEADER_SIZE         36

unsigned int byte2int(char *p)
{
    unsigned char *q = p;
    return q[0] | q[1] << 8 | q[2] << 16 | q[3] << 24;    
}

FilePart filePartArray[5];


unsigned int upd_total_cnt = 0;

int Cmd_Upgrade_V3_TX(PORT port,int dev,char *file_buf,int file_size,int upd_id)
{
    int i,j;
    int fsize;
    int fsize2 = 0;
    int ret;
    char *pfbuf = file_buf;

    unsigned char buffer[512];
    unsigned char pkg_ret[512];
    int totalframe;
    int nCurrentFrame = 0;
    int length;
    unsigned int sum;
    int wait_time;
    int need_retry = 0;
  
    while(read((int)port,pkg_ret,512) > 0);

//upgrade send data
    fsize = file_size;

    totalframe = (fsize + 495) / 496;

    while(1)
    {
        if(need_retry == 0)
        {
            /*
            length = read(fd,buffer + 16,496);
            if (length <= 0)
            {
                close(fd);
                return -1;
            }
            */
            length = min(fsize,496);
            memcpy((buffer + 16),pfbuf,length);
            pfbuf += length;
            fsize -= length;
            
            //fsize2 += (unsigned int)length;
            length += 6; //data length
    
            buffer[0] = 0xff;
            buffer[1] = 0x5a;
            buffer[2] = 0x01;
            buffer[3] = 0x00;
            buffer[4] = 0x01;
            buffer[5] = 0x00;
            buffer[6] = (char)length;
            buffer[7] = (char)(length >> 8);
    
            buffer[10] = (unsigned char)upd_id;
            buffer[11] = 0;
            buffer[12] = (char)nCurrentFrame;
            buffer[13] = (char)(nCurrentFrame >> 8);
            buffer[14] = (char)totalframe;                        
            buffer[15] = (char)(totalframe >> 8);
    
            //add check for frame
            for(i = 0,sum = 0;i < length;i ++)
            {
                sum += (unsigned char)buffer[i + 10];
            }
            buffer[8] = (char)sum;
            buffer[9] = (char)(sum >> 8);
        }
        
        upd_total_cnt += length;
        upd_total_cnt -= 6;

        ret = write((int)port,buffer,length + 10);

        if(nCurrentFrame < (totalframe - 1))
            wait_time = 200;
        else
            wait_time = 2000;
            
        //等待回应
        for(j = 0;j < wait_time;j ++)
        {
            usleep(10000);
            ret = read((int)port,pkg_ret,512);
            if(ret > 0)
            {
                //pkg okg
                if(pkg_ret[0] == 0xff && pkg_ret[1] == 0x5a && pkg_ret[2] == 0x6e)
                {
                    j = 0;
                    wait_time = 4000;
                    printf("send ok,wait for complete\n\n");

                }
                else if(pkg_ret[0] == 0xff && pkg_ret[1] == 0x5a 
                && pkg_ret[2] == 0x01 && pkg_ret[3] == 0x00 && pkg_ret[10] == 0x01)
                {
                    nCurrentFrame++;
                    if(nCurrentFrame == totalframe)
                    {
                        printf("========================================================\n");
                        printf("\t\tupgrade successed\n");
                        printf("========================================================\n");
                        return 0;
                    }
                    else
                       break;
                }
                //pkg failed
                else if(pkg_ret[0] == 0xff && pkg_ret[1] == 0x5a 
                && pkg_ret[2] == 0x01 && pkg_ret[3] == 0x00 && pkg_ret[10] == 0x00)
                {
                    //last pkg failed
                    if(wait_time == 2000)
                    {
                        printf("========================================================\n");
                        printf("upgrade failed ,Please restart the module and update it\n");
                        printf("========================================================\n");
                        return -1;
                    }
                    //common pkg failed
                    else
                    {
                        j = wait_time; 
                        break;
                    }
                }
                //pkg no ack
                else
                    continue;
            }
        }

        if(j == wait_time)
        {
            need_retry ++;
            if(need_retry > 5)
            {
                printf("========================================================\n");
                printf("upgrade failed ,Please restart the module and update it\n");
                printf("========================================================\n");
                return -1;
            }
        }   
        else
            need_retry = 0;
        
        printf("progress : %d / %d\n",nCurrentFrame,totalframe);

    }

    return 0;

}

int Cmd_Upgrade_Boot(PORT port,int dev,char *upgrade_file)
{

    int fd;
    int rret;
    int i;
    int ret;
    int total_part = 0;
    unsigned int length;
    unsigned int fsize;
    unsigned int file_len = 0;
    unsigned int file_len_total = 0;
    unsigned int sky_len;
    unsigned int grd_len;
    unsigned char pkg_ret[512];
    unsigned char upd_map[] = {0x02,0x03,0x04,0x00,0x05};
    MD5_CTX ctx;
    char bret;

    IMAGE_HEADER image_boot_header;
    UPGRADE_HEADER upgrade_boot_header;

    fd = open(upgrade_file, O_RDWR, S_IRUSR | S_IWUSR);
    if(fd < 0)
    {
        printf("upgrade file not exist\n");
        return -1;
    }

//-------------------------------- boot ---------------------------------------------    

    lseek(fd, FULLFILE_BOOT_POS, SEEK_SET);

//get image header

    length = sizeof(IMAGE_HEADER);
    rret = read(fd,(char*)&image_boot_header,length);
    if(rret != length)
    {
        printf("read file failed1\n");
        close(fd);
        return -1;
    }

//get total size from image header

    file_len =  byte2int(image_boot_header.appsize);
    printf("upgrade part len:%d\n",file_len);
    file_len_total = file_len + UPGRADE_HEADER_SIZE;

    filePartArray[0].file_data =(char*)malloc(file_len_total);
    filePartArray[0].size = file_len_total;

//make upgrade header
    lseek(fd, FULLFILE_BOOT_POS, SEEK_SET);

//body
    rret = read(fd,(char*)(filePartArray[0].file_data + UPGRADE_HEADER_SIZE),file_len);
    if(rret!= file_len)
    {
        printf("read file failed2\n");
        close(fd);
        return -1;
    }

    total_part ++;

//size    
    memcpy(upgrade_boot_header.image_size,&file_len_total,4);

    MD5Init(&ctx);
    MD5Update(&ctx,(char*)(filePartArray[0].file_data+UPGRADE_HEADER_SIZE),file_len);
    MD5Final(&ctx,pkg_ret);

//md5
    memcpy(upgrade_boot_header.MD5,pkg_ret,16);
    memcpy(upgrade_boot_header.EfuseMD5,pkg_ret,16);

//cp upgrade header to table1    
    memcpy(filePartArray[0].file_data,&upgrade_boot_header,UPGRADE_HEADER_SIZE);

    ret = Cmd_Upgrade_V3_TX(port,0,filePartArray[0].file_data,filePartArray[0].size,upd_map[0]);
    if(ret < 0)
    {
        printf("boot upgrade failed\n");
        return -1;
    }

    free(filePartArray[0].file_data);

    close(fd);


}


int Cmd_Upgrade_V3(PORT port,int dev,char *upgrade_file)
{
    int fd;
    int rret;
    int i;
    int ret;
    int total_part = 0;
    unsigned int length;
    unsigned int fsize;
    unsigned int file_len = 0;
    unsigned int file_len_total = 0;
    unsigned int sky_len;
    unsigned int grd_len;
    unsigned char pkg_ret[512];
    unsigned char upd_map[] = {0x02,0x03,0x04,0x00,0x05};

    MD5_CTX ctx;
    char bret;
    
    IMAGE_HEADER image_upd_header;
    IMAGE_HEADER image_updbak_header;
    IMAGE_HEADER image_sky_header;
    IMAGE_HEADER image_grd_header;
    IMAGE_HEADER image_appbak_header;
    
    UPGRADE_HEADER upgrade_upd_header;
    UPGRADE_HEADER upgrade_updbak_header;  
    UPGRADE_HEADER upgrade_app_header; 
    UPGRADE_HEADER upgrade_appbak_header; 
   
    while(read((int)port,pkg_ret,512) > 0);

//boot not in total file
    total_part ++;

//upgrade send data
    fsize = Get_File_Size(upgrade_file);
    printf("get file size: %d\n",fsize);

//boot upgrade
    if(fsize < 0xa000)
        return Cmd_Upgrade_Boot(port,dev,upgrade_file);

//app upgrade
    if(fsize < 0x300000)
        return Cmd_Upgrade_V2(port,dev,upgrade_file);

//total upgrade

    //totalframe = (fsize + 495) / 496;

    fd = open(upgrade_file, O_RDWR, S_IRUSR | S_IWUSR);
    if(fd < 0)
    {
        printf("upgrade file not exist\n");
        return -1;
    }
    
//-------------------------------- upgrade ---------------------------------------------    
    
    lseek(fd, FULLFILE_UPGRADE_POS, SEEK_SET);
    
//get image header
 
    length = sizeof(IMAGE_HEADER);
    rret = read(fd,(char*)&image_upd_header,length);
    if(rret != length)
    {
        printf("read file failed1\n");
        goto upd_tx;
    }

//get total size from image header
    
    file_len =  byte2int(image_upd_header.appsize);
    printf("upgrade part len:%d\n",file_len);
    file_len_total = file_len + UPGRADE_HEADER_SIZE;
    
    filePartArray[1].file_data =(char*)malloc(file_len_total);
    filePartArray[1].size = file_len_total; 
    
//make upgrade header
    lseek(fd, FULLFILE_UPGRADE_POS, SEEK_SET);

//body
    rret = read(fd,(char*)(filePartArray[1].file_data + UPGRADE_HEADER_SIZE),file_len);
    if(rret!= file_len)
    {
        printf("read file failed2\n");
        goto upd_tx;
    }
    
    total_part ++;
    
//size    
    memcpy(upgrade_upd_header.image_size,&file_len_total,4);
    
    MD5Init(&ctx);
    MD5Update(&ctx,(char*)(filePartArray[1].file_data+UPGRADE_HEADER_SIZE),file_len);
    MD5Final(&ctx,pkg_ret);
//md5

    memcpy(upgrade_upd_header.MD5,pkg_ret,16);
    memcpy(upgrade_upd_header.EfuseMD5,pkg_ret,16);
//cp upgrade header to table1    
    memcpy(filePartArray[1].file_data,&upgrade_upd_header,UPGRADE_HEADER_SIZE);
     
//--------------------------------upgrade backup-------------------------------------------

    lseek(fd, FULLFILE_UPGRADEBAK_POS, SEEK_SET);
    length = sizeof(IMAGE_HEADER);
    rret = read(fd,(char*)&image_updbak_header,length);
    if(rret != length)
    {
        printf("read file error3\n");
        goto upd_tx;
    }
    
    file_len =  byte2int(image_updbak_header.appsize);
    file_len_total = file_len + UPGRADE_HEADER_SIZE;
    printf("imagebak_header:%d\n",file_len);
    
    filePartArray[2].file_data =(char*)malloc(file_len_total);
    filePartArray[2].size = file_len_total;
    lseek(fd, FULLFILE_UPGRADEBAK_POS, SEEK_SET);
    
    rret = read(fd,(char*)(filePartArray[2].file_data + UPGRADE_HEADER_SIZE),file_len);
    if(rret != file_len)
    {
        printf("read file error4\n");
        goto upd_tx;
    }
    
    total_part ++;
        
    memcpy(upgrade_updbak_header.image_size,&file_len_total,4);
    
    MD5Init(&ctx);
    MD5Update(&ctx,(char*)(filePartArray[2].file_data+UPGRADE_HEADER_SIZE),file_len);
    MD5Final(&ctx,pkg_ret);
//md5
    memcpy(upgrade_updbak_header.MD5,pkg_ret,16);
    memcpy(upgrade_updbak_header.EfuseMD5,pkg_ret,16);
    memcpy(filePartArray[2].file_data,&upgrade_updbak_header,UPGRADE_HEADER_SIZE);
  
//-------------------------------- app -------------------------------------------

    lseek(fd, FULLFILE_APP_POS, SEEK_SET);

    length = sizeof(IMAGE_HEADER);
    rret = read(fd,(char*)&image_sky_header,length);
    if(rret != length)
    {
        printf("read file error5\n");
        goto upd_tx;
    }
    
    sky_len =  byte2int(image_sky_header.appsize);
    printf("app sky len:%d\n",sky_len);
    
    lseek(fd, (FULLFILE_APP_POS+sky_len), SEEK_SET);
    
    length = sizeof(IMAGE_HEADER);
    rret = read(fd,(char*)&image_grd_header,length);
    if(rret != length)
    {
        printf("read file error6\n");
        goto upd_tx;
    }
    
    grd_len =  byte2int(image_grd_header.appsize);
    printf("app grd len:%d\n",grd_len);
    
    file_len_total = sky_len + grd_len + UPGRADE_HEADER_SIZE;
    filePartArray[3].file_data =(char*)malloc(file_len_total);
    filePartArray[3].size = file_len_total;
    
    lseek(fd, FULLFILE_APP_POS, SEEK_SET);

    rret = read(fd,(char*)(filePartArray[3].file_data+UPGRADE_HEADER_SIZE),(sky_len + grd_len));
    if(rret != (sky_len + grd_len))
    {
        printf("read file error7\n");
        goto upd_tx;
    }
    
    total_part ++;
    
    memcpy(upgrade_app_header.image_size,&file_len_total,4);
    
    MD5Init(&ctx);
    MD5Update(&ctx,(char*)(filePartArray[3].file_data+UPGRADE_HEADER_SIZE),(sky_len + grd_len));
    MD5Final(&ctx,pkg_ret);
//md5
    memcpy(upgrade_app_header.MD5,pkg_ret,16);
    memcpy(upgrade_app_header.EfuseMD5,pkg_ret,16);
    memcpy(filePartArray[3].file_data,&upgrade_app_header,UPGRADE_HEADER_SIZE);
  
//-------------------------------- app backup-------------------------------------------

    lseek(fd, FULLFILE_APPBAK_POS, SEEK_SET);
    
    length = sizeof(IMAGE_HEADER);
    rret = read(fd,(char*)&image_appbak_header,length);
    if(rret != length)
    {
        printf("read file error8\n");
        goto upd_tx;
    }
    
    file_len =  byte2int(image_appbak_header.appsize);
    file_len_total = file_len+UPGRADE_HEADER_SIZE;
    filePartArray[4].file_data =(char*)malloc(file_len_total);
    filePartArray[4].size = file_len_total;
  
    lseek(fd, FULLFILE_APPBAK_POS, SEEK_SET);

    rret = read(fd,(char*)(filePartArray[4].file_data+UPGRADE_HEADER_SIZE),file_len);
    if(rret != file_len)
    {
        printf("read file error9\n");
        goto upd_tx;
    }
    
    total_part ++;
    
    memcpy(upgrade_appbak_header.image_size,&file_len_total,4);
  
    MD5Init(&ctx);
    MD5Update(&ctx,(char*)(filePartArray[4].file_data+UPGRADE_HEADER_SIZE),file_len);
    MD5Final(&ctx,pkg_ret);
//md5
    memcpy(upgrade_appbak_header.MD5,pkg_ret,16);
    memcpy(upgrade_appbak_header.EfuseMD5,pkg_ret,16);
    memcpy(filePartArray[4].file_data,&upgrade_appbak_header,UPGRADE_HEADER_SIZE);

upd_tx:
    
    printf("total part: %d\n",total_part);
    if(total_part > 2)
    {
        for(i = 1;i < total_part;i ++)
        {
            ret = Cmd_Upgrade_V3_TX(port,0,filePartArray[i].file_data,filePartArray[i].size,upd_map[i]);
            if(ret < 0)
                break;

            usleep(5000000);
        }
        
        for(i = 1;i < total_part;i ++)
            free(filePartArray[i].file_data);
            
        close(fd);
    }

    printf("upd total cnt : %x\n",upd_total_cnt);

}

int Get_Upgrade_Version(PORT port,char *buf)
{
    int ret;
    int i;
    unsigned char buffer[512];
    unsigned char pkg_ret[512];
 
    while(read((int)port,pkg_ret,512) > 0);

    //check protocol
    buffer[0] = 0xff;
    buffer[1] = 0x5a;
    buffer[2] = 0x00;
    buffer[3] = 0x00;
    buffer[4] = 0x01;
    buffer[5] = 0x00;
    buffer[6] = 0x00;
    buffer[7] = 0x00;
    buffer[8] = 0x00;
    buffer[9] = 0x00;

    if(write((int)port,buffer,10) != 10)
    {
        printf("usb send err\n");
        return -1;
    }

    usleep(100000);

    ret = read((int)port,pkg_ret,512);
    if(ret > 0)
    {
        //for(i = 0;i < ret;i ++)
        //printf("%x ",pkg_ret[i]);
        //printf("\n");
 
        if(pkg_ret[0] == 0xff && pkg_ret[1] == 0x5a && pkg_ret[2] == 0x00 && pkg_ret[3] == 0x00)
        {
            memcpy(buf,&pkg_ret[11],4);
            return 0;
        }
    }
    
    printf("get version err\n");
    return -1;

}

int Cmd_Upgrade(PORT port,int dev,char *upgrade_file)
{
    unsigned char state = 0;
    unsigned char buffer[512];
    unsigned char pkg_ret[512];
    
    if(upgrade_file == NULL)
    {
        printf("no upgrade file\n");
        return -1;
    }
//start upgrade
    ioctl((int)port,UPGRADE_START,0);

    usleep(100000);
    if(Get_Upgrade_Version(port,pkg_ret) < 0)
    {
        Cmd_Upgrade_V1(port,dev,upgrade_file);
    }
    /*
    else if(pkg_ret[0] == '1' && pkg_ret[1] == '.' && pkg_ret[2] == '0' && pkg_ret[3] == '1')
    {
        Cmd_Upgrade_V2(port,dev,upgrade_file);
    }
    */
    //version 1.0.1 ande version 1.0.2
    else if(pkg_ret[0] == '1' && pkg_ret[1] == '.' && pkg_ret[2] == '0' && (pkg_ret[3] == '2' || pkg_ret[3] == '1'))
    {
        Cmd_Upgrade_V3(port,dev,upgrade_file);
    }
    else
    {
        printf("version err:\n");
        printf("current version:%c%c%c%c\n",pkg_ret[0],pkg_ret[1],pkg_ret[2],pkg_ret[3]);
        printf("support version list:\n\t1.01\n");
    }
  
}

int Video_Port_Rec(PORT port,char *data,int count)
{
    int ret;

    if(port == NULL || data == NULL)
        return -1;
    ret = read((int)port,data,count);

    return ret;
}

int Video_Port_Send(PORT port,char *data,int count)
{
    int ret;
    int usr_data_len;
    unsigned long usr_data;
    char head[20];
    int i;
 
    if(port == NULL || data == NULL || count < 1)
        return -1;

    usr_data_len = min(count, (size_t)(MAX_TRANSFER - 8));

    head[0] = 0x12;    //head
    head[1] = 0x34;    //head
    head[2] = 0x56;    //head
    head[3] = 0x0;     //id
    
    head[4] = (char)(usr_data_len >> 24);   //usr data len
    head[5] = (char)(usr_data_len >> 16);   //usr data len
    head[6] = (char)(usr_data_len >> 8);    //usr data len
    head[7] = (char)usr_data_len;           //usr data len

    head[8] = sizeof(data);                

    if(head[8] == 4)
        usr_data = (unsigned int)data;
    else if(head[8] == 8)
        usr_data = (unsigned long)data;
    else
        return -1;

    for(i = 0;i < head[8];i++)
    {
        head[9 + i] = (char)(usr_data >> (8 * (head[8] - i - 1)));
    }

    pthread_mutex_lock(&port1_mutex);
    ret = write((int)port,head,20);
    pthread_mutex_unlock(&port1_mutex); 
    
    return ret; 

}

int Audio_Port_Rec(PORT port,char *data,int count)
{
    int ret;

    if(port == NULL || data == NULL)
        return -1;
    ret = read((int)port,data,count);

    return ret;
}

int Audio_Port_Send(PORT port,char *data,int count)
{
    int ret;
    int usr_data_len;
    unsigned long usr_data;
    char head[20];
    int i;
 
    if(port == NULL || data == NULL || count < 1)
        return -1;

    usr_data_len = min(count, (size_t)(MAX_TRANSFER - 8));

    head[0] = 0x12;    //head
    head[1] = 0x34;    //head
    head[2] = 0x56;    //head
    head[3] = 0x1;     //id
    
    head[4] = (char)(usr_data_len >> 24);   //usr data len
    head[5] = (char)(usr_data_len >> 16);   //usr data len
    head[6] = (char)(usr_data_len >> 8);    //usr data len
    head[7] = (char)usr_data_len;           //usr data len

    head[8] = sizeof(data);                

    if(head[8] == 4)
        usr_data = (unsigned int)data;
    else if(head[8] == 8)
        usr_data = (unsigned long)data;
    else
        return -1;

    for(i = 0;i < head[8];i++)
    {
        head[9 + i] = (char)(usr_data >> (8 * (head[8] - i - 1)));
    }

    pthread_mutex_lock(&port1_mutex);
    ret = write((int)port,head,20);
    pthread_mutex_unlock(&port1_mutex); 
    
    return ret; 
}

int Pkg_Rec(PORT port,char *data,int count)
{
    int ret;

    if(port == NULL || data == NULL)
        return -1;
    
    if(count < MAX_PKG_LEN)
    {
        printf("rec buf too small\n");
        return 0;        
    }
    ret = read((int)port,data,count);

    return ret;
}

int Pkg_Send(PORT port,char *data,int count)
{
    int ret;
    int usr_data_len;
    int usr_data = (int)data;
    char head[12];
    
    
    if(port == NULL || data == NULL || count < 1)
        return -1;
        
    if(count > MAX_PKG_LEN)
    {
        printf("out of pkg range\n");
        return 0;
    }
    
    head[0] = 0x12;    //head
    head[1] = 0x34;    //head
    head[2] = 0x56;    //head
    head[3] = 0x0;     //id
    
    head[4] = (char)(count >> 24);       //usr data len
    head[5] = (char)(count >> 16);       //usr data len
    head[6] = (char)(count >> 8);        //usr data len
    head[7] = (char)count;               //usr data len
    
    head[8] = (char)(usr_data >> 24);    //data addr
    head[9] = (char)(usr_data >> 16);    //data addr
    head[10] = (char)(usr_data >> 8);    //data addr
    head[11] = (char)usr_data;           //data addr

    pthread_mutex_lock(&port1_mutex); 
    ret = write((int)port,&head,sizeof(head));
    pthread_mutex_unlock(&port1_mutex); 
    
    return ret; 
    
}

int Usb_Init(void)
{
    int ret;
    int port0;
    int port1;
    
    pthread_mutex_init(&port0_mutex, NULL);
    pthread_mutex_init(&port1_mutex, NULL);
    
    port0 = open("/dev/artosyn_port0", O_RDWR, S_IRUSR | S_IWUSR);
    if(port0 < 0)
    {
        return port0;
    }
    port1 = open("/dev/artosyn_port1", O_RDWR, S_IRUSR | S_IWUSR);
    if(port1 < 0)
    {
        return port1;
    }
    
    ret = ioctl((int)port0,CMD_BYPASS_MODE,0);
    if(ret < 0)
        return ret;

    ret = ioctl((int)port1,TX_PARSE_MODE,0);
    if(ret < 0)
        return ret;

    close(port0);
    close(port1);
    
    return 0;
}

int Cmd_Port_Close(PORT port)
{
    close((int)port);
}

int Video_Port_Close(PORT port)
{
    
    close((int)port);
}

int Audio_Port_Close(PORT port)
{
    close((int)port);
}

int Pkg_Close(PORT port)
{
    
    close((int)port);
}

int Usb_Exit(void)
{
    pthread_mutex_destroy(&port0_mutex);
    pthread_mutex_destroy(&port1_mutex);

}


