/*=============================================================================
#     FileName: main.c
#         Desc: this program aim to get yuyv image from USB camera  used the V4L2
#		 interface, and then encoder to h264 used the libx264
#       Author: licaibiao
#      Version: 
#   LastChange: 20170221
=============================================================================*/
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <linux/types.h>
#include <linux/videodev2.h>
#include <malloc.h>
#include <math.h>
#include <string.h>
#include <sys/mman.h>
#include <errno.h>
#include <assert.h>
#include "./include/h264encoder.h"
#if 0
#define WIDTH		640
#define	HIGHT		480
#else
#define WIDTH		1280
#define	HIGHT		800
#endif
#define COUNT		2000
#define FILE_VIDEO      "/dev/video0"

char h264_file_name[20] = "./out/test.h264";
char *h264_buf;
static unsigned int n_buffer = 0;
Encoder en;
FILE *h264_fp;

typedef struct{
    void *start;
	int length;
}BUFTYPE;
BUFTYPE *usr_buf;

void init_encoder(int width, int height)
{
	int test;
	compress_begin(&en, width, height);
	h264_buf = (char *) malloc( width * height * 2);	
}

void init_file() {
	printf("file:%s fun:%s line:%d\n", __FILE__, __FUNCTION__, __LINE__);

	h264_fp = fopen(h264_file_name, "wa+");
	if(NULL == h264_fp)
		printf("file:%s fun:%s line:%d    h264file open error %s\n", __FILE__, __FUNCTION__, __LINE__, strerror(errno));
}

void close_encoder() {
	compress_end(&en);
	free(h264_buf);
}

void close_file() {
	fclose(h264_fp);
}

void encode_frame(uint8_t *yuv_frame, size_t yuv_length) 
{
	int h264_length = 0;
	static int count = 0;
	//printf("file:%s fun:%s line:%d\n", __FILE__, __FUNCTION__, __LINE__);
	h264_length = compress_frame(&en, -1, yuv_frame, h264_buf);
	//printf("file:%s fun:%s line:%d\n", __FILE__, __FUNCTION__, __LINE__);
	if (h264_length > 0)
	{	
		//printf("file:%s fun:%s line:%d  h264_length:%d\n", __FILE__, __FUNCTION__, __LINE__, h264_length);
		if(NULL == h264_fp)
			printf("h264_fp is null\n");
		if(fwrite(h264_buf, h264_length, 1, h264_fp)>0)
		{
			printf("encode_frame num = %d\n",count++);
		}
		else
		{
			perror("encode_frame fwrite err\n");
		}
				
	}
	//printf("file:%s fun:%s line:%d\n", __FILE__, __FUNCTION__, __LINE__);
}


/*set video capture ways(mmap)*/
int init_mmap(int fd)
{
	/*to request frame cache, contain requested counts*/
	struct v4l2_requestbuffers reqbufs;

	memset(&reqbufs, 0, sizeof(reqbufs));
	reqbufs.count = 4; 	 							/*the number of buffer*/
	reqbufs.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;    
	reqbufs.memory = V4L2_MEMORY_MMAP;				

	if(-1 == ioctl(fd,VIDIOC_REQBUFS,&reqbufs))
	{
		perror("Fail to ioctl 'VIDIOC_REQBUFS'");
		exit(EXIT_FAILURE);
	}
	
	n_buffer = reqbufs.count;
	printf("n_buffer = %d\n", n_buffer);
	//usr_buf = calloc(reqbufs.count, sizeof(usr_buf));
	usr_buf = calloc(reqbufs.count, sizeof(BUFTYPE));
	if(usr_buf == NULL)
	{
		printf("Out of memory\n");
		exit(-1);
	}

	/*map kernel cache to user process*/
	for(n_buffer = 0; n_buffer < reqbufs.count; ++n_buffer)
	{
		//stand for a frame
		struct v4l2_buffer buf;
		memset(&buf, 0, sizeof(buf));
		buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		buf.memory = V4L2_MEMORY_MMAP;
		buf.index = n_buffer;
		
		/*check the information of the kernel cache requested*/
		if(-1 == ioctl(fd,VIDIOC_QUERYBUF,&buf))
		{
			perror("Fail to ioctl : VIDIOC_QUERYBUF");
			exit(EXIT_FAILURE);
		}

		usr_buf[n_buffer].length = buf.length;
		usr_buf[n_buffer].start = (char *)mmap(NULL,buf.length,PROT_READ | PROT_WRITE,MAP_SHARED, fd,buf.m.offset);

		if(MAP_FAILED == usr_buf[n_buffer].start)
		{
			perror("Fail to mmap");
			exit(EXIT_FAILURE);
		}

	}

}

int open_camera(void)
{
	int fd;
	struct v4l2_input inp;

	//fd = open(FILE_VIDEO, O_RDWR | O_NONBLOCK,0);//Fail to ioctl 'VIDIOC_DQBUF': Resource temporarily unavailable
	fd = open(FILE_VIDEO, O_RDWR);
	if(fd < 0)
	{	
		fprintf(stderr, "%s open err \n", FILE_VIDEO);
		exit(EXIT_FAILURE);
	};

	inp.index = 0;
	if (-1 == ioctl (fd, VIDIOC_S_INPUT, &inp))
	{
		fprintf(stderr, "VIDIOC_S_INPUT \n");
	}

	return fd;
}

int init_camera(int fd)
{
	struct v4l2_capability 	cap;		/* decive fuction, such as video input */
	struct v4l2_format 	tv_fmt;		/* frame format */  
	struct v4l2_fmtdesc 	fmtdesc;  	/* detail control value */
	struct v4l2_control 	ctrl;
	int ret;
	
	
	memset(&fmtdesc, 0, sizeof(fmtdesc));
	fmtdesc.index = 0 ;                	/* the number to check */
	fmtdesc.type=V4L2_BUF_TYPE_VIDEO_CAPTURE;

	/* check video decive driver capability */
	if(ret=ioctl(fd, VIDIOC_QUERYCAP, &cap)<0)
	{
		fprintf(stderr, "fail to ioctl VIDEO_QUERYCAP \n");
		exit(EXIT_FAILURE);
	}
	
	/*judge wherher or not to be a video-get device*/
	if(!(cap.capabilities & V4L2_BUF_TYPE_VIDEO_CAPTURE))
	{
		fprintf(stderr, "The Current device is not a video capture device \n");
		exit(EXIT_FAILURE);
	}

	/*judge whether or not to supply the form of video stream*/
	if(!(cap.capabilities & V4L2_CAP_STREAMING))
	{
		printf("The Current device does not support streaming i/o\n");
		exit(EXIT_FAILURE);
	}
	
	printf("\ncamera driver name is : %s\n",cap.driver);
	printf("camera device name is : %s\n",cap.card);
	printf("camera bus information: %s\n",cap.bus_info);
#if 1
	/*show all the support format*/
	printf("\n");
	while(ioctl(fd,VIDIOC_ENUM_FMT,&fmtdesc)!=-1)
	{	
		printf("support device %d.%s\n",fmtdesc.index+1,fmtdesc.description);
		fmtdesc.index++;
	}
	printf("\n");
#endif
#if 1 //check camera if support format
	struct v4l2_format fmt_check;
	fmt_check.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	fmt_check.fmt.pix.pixelformat = V4L2_PIX_FMT_YUYV;
	if(ioctl(fd, VIDIOC_TRY_FMT, &fmt_check) == -1)
	{
		printf("the camera not support V4L2_PIX_FMT_YUYV\n");
	}
	else
	{
		printf("the camera is support V4L2_PIX_FMT_YUYV\n");
	}
#endif

	/*set the form of camera capture data*/
	tv_fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;      /*v4l2_buf_typea,camera must use V4L2_BUF_TYPE_VIDEO_CAPTURE*/
#if 1
	tv_fmt.fmt.pix.width = WIDTH;
	tv_fmt.fmt.pix.height = HIGHT;
#else
	tv_fmt.fmt.pix.width = 1280;
	tv_fmt.fmt.pix.height = 800;
#endif
	//tv_fmt.fmt.pix.pixelformat = V4L2_PIX_FMT_YUV420;	/*V4L2_PIX_FMT_YYUV*/
#if 1
	tv_fmt.fmt.pix.pixelformat = V4L2_PIX_FMT_YUYV;	/*V4L2_PIX_FMT_YYUV*/
#else
	//tv_fmt.fmt.pix.pixelformat = V4L2_PIX_FMT_YUV422;	/*V4L2_PIX_FMT_YYUV*/
#endif
	//tv_fmt.fmt.pix.field = V4L2_FIELD_NONE;   		/*V4L2_FIELD_NONE*/
	tv_fmt.fmt.pix.field = V4L2_FIELD_INTERLACED;   	/*V4L2_FIELD_NONE*/
	if (ioctl(fd, VIDIOC_S_FMT, &tv_fmt)< 0) 
	{
		fprintf(stderr,"VIDIOC_S_FMT set err\n");
		exit(-1);
		close(fd);
	}
#if 1
	 struct v4l2_streamparm stream_para;
	//设置及查看帧速率，这里只能是30帧，就是1秒采集30张图
	memset(&stream_para, 0, sizeof(struct v4l2_streamparm));
	stream_para.type = V4L2_BUF_TYPE_VIDEO_CAPTURE; 
	stream_para.parm.capture.timeperframe.denominator = 30;
	stream_para.parm.capture.timeperframe.numerator = 1;

	if(ioctl(fd, VIDIOC_S_PARM, &stream_para) == -1)
	{
		printf("Unable to set frame rate\n");
		return -1;
	}

	if(ioctl(fd, VIDIOC_G_PARM, &stream_para) == -1)
    {
        printf("Unable to get frame rate\n");
        return -1;       
    }
    {
        printf("numerator:%d\ndenominator:%d\n",stream_para.parm.capture.timeperframe.numerator,stream_para.parm.capture.timeperframe.denominator);
    }

#endif




	init_mmap(fd);
	init_encoder(WIDTH, HIGHT);
	init_file();
}

int start_capture(int fd)
{
	unsigned int i;
	enum v4l2_buf_type type;
	
	/*place the kernel cache to a queue*/
	for(i = 0; i < n_buffer; i++)
	{
		struct v4l2_buffer buf;
		memset(&buf, 0, sizeof(buf));
		buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		buf.memory = V4L2_MEMORY_MMAP;
		buf.index = i;

		if(-1 == ioctl(fd, VIDIOC_QBUF, &buf))
		{
			perror("Fail to ioctl 'VIDIOC_QBUF'");
			exit(EXIT_FAILURE);
		}
	}

	type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	if(-1 == ioctl(fd, VIDIOC_STREAMON, &type))
	{
		printf("i=%d.\n", i);
		perror("VIDIOC_STREAMON");
		close(fd);
		exit(EXIT_FAILURE);
	}

	return 0;
}


int read_frame(int fd)
{
	struct v4l2_buffer buf;
	unsigned int i;
	memset(&buf, 0, sizeof(buf));
	buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	buf.memory = V4L2_MEMORY_MMAP;
	printf("file:%s fun:%s line:%d\n", __FILE__, __FUNCTION__, __LINE__);
	//put cache from queue
	if(-1 == ioctl(fd, VIDIOC_DQBUF,&buf))
	{
		perror("Fail to ioctl 'VIDIOC_DQBUF'");
		exit(EXIT_FAILURE);
	}
	printf("file:%s fun:%s line:%d\n", __FILE__, __FUNCTION__, __LINE__);
	assert(buf.index < n_buffer);
	printf("file:%s fun:%s line:%d\n", __FILE__, __FUNCTION__, __LINE__);
	encode_frame(usr_buf[buf.index].start, usr_buf[buf.index].length);
	printf("file:%s fun:%s line:%d\n", __FILE__, __FUNCTION__, __LINE__);
	if(-1 == ioctl(fd, VIDIOC_QBUF,&buf))
	{
		perror("Fail to ioctl 'VIDIOC_QBUF'");
		exit(EXIT_FAILURE);
	}
	//printf("file:%s fun:%s line:%d\n", __FILE__, __FUNCTION__, __LINE__);
	return 1;
}


int mainloop(int fd)
{
	int count = COUNT;
	while(count-- > 0)
	{
		for(;;)
		{
			fd_set fds;
			struct timeval tv;
			int r;

			FD_ZERO(&fds);
			FD_SET(fd,&fds);

			/*Timeout*/
			tv.tv_sec = 5;
			tv.tv_usec = 0;
			//r = select(fd + 1,&fds,NULL,NULL,&tv);
			r = select(fd + 1,&fds,NULL,NULL,NULL);
			if(-1 == r)
			{
				 if(EINTR == errno)
					continue;
				perror("Fail to select");
				exit(EXIT_FAILURE);
			}
			if(0 == r)
			{
				fprintf(stderr,"select Timeout\n");
				//exit(-1);
			}
			//printf("file:%s fun:%s line:%d\n", __FILE__, __FUNCTION__, __LINE__);
			if(read_frame(fd))
			{
			printf("read frame return error\n");
			break;
			}
		}
	}
	return 0;
}

void stop_capture(int fd)
{
	enum v4l2_buf_type type;
	type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	if(-1 == ioctl(fd,VIDIOC_STREAMOFF,&type))
	{
		perror("Fail to ioctl 'VIDIOC_STREAMOFF'");
		exit(EXIT_FAILURE);
	}
}

void close_camera_device(int fd)
{
	unsigned int i;
	close_encoder();
	close_file();

	for(i = 0;i < n_buffer; i++)
	{
		if(-1 == munmap(usr_buf[i].start,usr_buf[i].length))
		{
			exit(-1);
		}
	}

	free(usr_buf);
	if(-1 == close(fd))
	{
		perror("Fail to close fd");
		exit(EXIT_FAILURE);
	}
}

void main(void)
{
	int fd;
	float dt;
	struct timeval now, start;

	fd = open_camera();
	init_camera(fd);
	start_capture(fd);
printf("file:%s fun:%s line:%d\n", __FILE__, __FUNCTION__, __LINE__);
	gettimeofday(&start,NULL);
	printf("file:%s fun:%s line:%d\n", __FILE__, __FUNCTION__, __LINE__);
	mainloop(fd);
	printf("file:%s fun:%s line:%d\n", __FILE__, __FUNCTION__, __LINE__);
	gettimeofday(&now,NULL);
	dt = (float)(now.tv_sec  - start.tv_sec);
	dt += (float)(now.tv_usec - start.tv_usec) * 1e-6;
	printf("spend time %f s\n ",dt);

	stop_capture(fd);
	close_camera_device(fd);
}




