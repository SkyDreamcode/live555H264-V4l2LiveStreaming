/*============================================================================= 
 *     FileName: sockInit.cpp 
 *         Desc: 
 *       Author: licaibiao 
 *   LastChange: 2017-05-3  
 * =============================================================================*/ 


#ifdef WIN32
#include <windows.h>
#pragma comment(lib,"WS2_32.lib")
#pragma comment(lib,"winmm.lib")
#endif
/**
 * ��ʼ��winsock
 *
 * @�ɹ��򷵻�1 , ʧ���򷵻���Ӧ�������
 */
int InitSockets()
{
	#ifdef WIN32
		WORD version;
		WSADATA wsaData;
		version = MAKEWORD(1, 1);
		return (WSAStartup(version, &wsaData) == 0);
	#else
		return 1;
	#endif
}

/**
 * �ͷ�winsock
 *
 * @�ɹ��򷵻�0 , ʧ���򷵻���Ӧ�������
 */
void CleanupSockets()
{
	#ifdef WIN32
		WSACleanup();
	#endif
}

