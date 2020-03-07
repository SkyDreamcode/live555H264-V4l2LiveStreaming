#include <stdio.h>
#include "librtmp_send264.h"



FILE *fp_send1;

//���ļ��Ļص�����
//we use this callback function to read data from buffer
int read_buffer1(unsigned char *buf, int buf_size ){
	if(!feof(fp_send1)){
		int true_size=fread(buf,1,buf_size,fp_send1);
		return true_size;
	}else{
		return -1;
	}
}

int main(int argc, char* argv[])
{
	fp_send1 = fopen("cuc_ieschool.h264", "rb");

	//��ʼ�������ӵ�������
	RTMP264_Connect("rtmp://192.168.0.5:1935/live");
	
	//����
	RTMP264_Send(read_buffer1);

	//�Ͽ����Ӳ��ͷ������Դ
	RTMP264_Close();

	return 0;
}

