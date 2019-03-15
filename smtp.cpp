// build-up-mstp.cpp : Defines the entry point for the console application.
//


#include "smtp.h"
#include <iostream>
#include <fstream>

using namespace std;

#pragma  comment(lib, "ws2_32.lib") /*����ws2_32.lib��̬���ӿ�*/
/* ������opencvһ����Ҫ������ӿ⺯����cv.lib�ȣ�Ҫ��ӵ����������
����ͨ��#pragma comment��lib, ��cv.lib����һ����Ȼ����ܰ���ͷ�ļ����и��ֺ����ĵ���
*socket���Ҫ���ø���socket������������Ҫ��Ws2_32.lib��ͷ�ļ�Winsock2.h*/

/*base64���ñ��˵ı���,�������ⲻ���ص㣬�ص�����������ҵ�һ���ȽϺõ��ʼ����Ϳͻ���*/

char* CSmtp::base64Encode(char const* origSigned, unsigned origLength) {
	unsigned char const* orig = (unsigned char const*)origSigned; // in case any input bytes have the MSB set
	if (orig == NULL) return NULL;

	unsigned const numOrig24BitValues = origLength / 3;
	bool havePadding = origLength > numOrig24BitValues * 3;  //origLength����3�ı���
	bool havePadding2 = origLength == numOrig24BitValues * 3 + 2;  //origLength MOD3 =2
	unsigned const numResultBytes = 4 * (numOrig24BitValues + havePadding);
	char* result = new char[numResultBytes + 3]; // allow for trailing '/0'

												 // Map each full group of 3 input bytes into 4 output base-64 characters:
	unsigned i;
	for (i = 0; i < numOrig24BitValues; ++i)
	{
		result[4 * i + 0] = base64Char[(orig[3 * i] >> 2) & 0x3F];
		result[4 * i + 1] = base64Char[(((orig[3 * i] & 0x3) << 4) | (orig[3 * i + 1] >> 4)) & 0x3F];
		result[4 * i + 2] = base64Char[((orig[3 * i + 1] << 2) | (orig[3 * i + 2] >> 6)) & 0x3F];
		result[4 * i + 3] = base64Char[orig[3 * i + 2] & 0x3F];
	}

	// Now, take padding into account.  (Note: i == numOrig24BitValues)
	if (havePadding)
	{
		result[4 * i + 0] = base64Char[(orig[3 * i] >> 2) & 0x3F];
		if (havePadding2)
		{
			result[4 * i + 1] = base64Char[(((orig[3 * i] & 0x3) << 4) | (orig[3 * i + 1] >> 4)) & 0x3F];
			result[4 * i + 2] = base64Char[(orig[3 * i + 1] << 2) & 0x3F];
		}
		else
		{
			result[4 * i + 1] = base64Char[((orig[3 * i] & 0x3) << 4) & 0x3F];
			result[4 * i + 2] = '=';
		}
		result[4 * i + 3] = '=';
	}
}



CSmtp::CSmtp(void)  //Ĭ�Ϲ��캯��
{
	this->content = "";
	this->port = 25;
	this->user = "";
	this->pass = "";
	this->targetAddr = "";
	this->title = "";
	this->domain = "";

	WORD wVersionRequested;  //����C++��׼�����ͣ���΢��SDK�е����ͣ�WORD����˼Ϊ�֣���2byte���޷�����������ʾ��Χ0~65535. 
	WSADATA wsaData;
	//WSADATA��һ�����ݽṹ������ṹ�������洢��WSAStartup�������ú󷵻ص�Windows Sockets���ݡ�������Winsock.dllִ�е�����


	/*�����ṹԭ�ͣ�����
	struct WSAData {
	����WORD wVersion;  ��λ�ֽڴ洢���汾��, ��λ�ֽڴ洢���汾�ţ�������WORD MAKEWORD(BYTE,BYTE ) �������ֵ,����:MAKEWORD(1,1)
	  ����WORD wHighVersion;  ���DLL�ܹ�֧�ֵ�Windows Sockets�淶����߰汾��ͨ������wVersion��ͬ��
		����char szDescription[WSADESCRIPTION_LEN+1]; ��null��β��ASCII�ַ�����Windows Sockets DLL����Windows Socketsʵ�ֵ���������������ַ����У����������̱�ʶ��
		  ����char szSystemStatus[WSASYSSTATUS_LEN+1]; ��null��β��ASCII�ַ�����Windows Sockets DLL���йص�״̬��������Ϣ���������ַ����С�Windows Sockets DLLӦ��������Щ��Ϣ���û���֧����Ա����ʱ��ʹ�����ǣ�����Ӧ����ΪszDescription�����չ��
			����unsigned short iMaxSockets;  ���������ܹ��򿪵�socket�������Ŀ
			  ����unsigned short iMaxUdpDg;  �ܹ����ͻ���յ������û����ݰ�Э�飨UDP�������ݰ���С�����ֽ�Ϊ��λ�����ʵ�ַ�ʽû�����ƣ���ôiMaxUdpDgΪ�㡣
				����char *lpVendorInfo;}; ָ�������̵����ݽṹ��ָ�롣����ṹ�Ķ��壨����У�������WindowsSockets�淶�ķ�Χ��WinSock2.0�����ѱ�������
				  */


	int err;
	//makeword�ǽ�����byte�ͺϲ���һ��word�ͣ�һ���ڸ�8λ(b)��һ���ڵ�8λ(a)  00000001 00000010
	//����Ҫʹ��2.1�汾��Socket,��ô���������������
	wVersionRequested = MAKEWORD(2, 1);

	/*�����WSAStartup����Ϊ�������ϵͳ˵��������Ҫ���ĸ����ļ���
	�øÿ��ļ��뵱ǰ��Ӧ�ó���󶨣��Ӷ��Ϳ��Ե��øð汾��socket�ĸ��ֺ����ˡ�*/
	err = WSAStartup(wVersionRequested, &wsaData);
	this->sockClient = 0;
}


CSmtp::~CSmtp(void)  //��������
{
	DeleteAllAttachment();
	closesocket(sockClient);
	WSACleanup();
	/*
	int WSACleanup (void);
	Ӧ�ó�������ɶ������Socket���ʹ�ú�
	Ҫ����WSACleanup�����������Socket��İ󶨲����ͷ�Socket����ռ�õ�ϵͳ��Դ��
	*/
}

CSmtp::CSmtp(   //���캯��
	int port,
	std::string srvDomain,
	std::string userName,
	std::string password,
	std::string targetEmail,
	std::string emailTitle,
	std::string content
)
{
	this->content = content;
	this->port = port;
	this->user = userName;
	this->pass = password;
	this->targetAddr = targetEmail;
	this->title = emailTitle;
	this->domain = srvDomain;

	WORD wVersionRequested;

	WSADATA wsaData;
	int err;
	wVersionRequested = MAKEWORD(2, 1);
	err = WSAStartup(wVersionRequested, &wsaData);
	this->sockClient = 0;
}

bool CSmtp::CreateConn()
{
	//Ϊ����socket������׼������ʼ������
	SOCKET sockClient = socket(AF_INET, SOCK_STREAM, 0); //����socket����    /* ������ */
														 //int socket(int domain, int type, int protocol);

	SOCKADDR_IN addrSrv;

	/*
	struct sockaddr_in {
	short int sin_family;       ͨ������
	unsigned short int sin_port;    �˿�
	struct in_addr sin_addr;     Internet ��ַ
	unsigned char sin_zero[8];    ��sockaddr�ṹ�ĳ�����ͬ
	};
	*/

	HOSTENT* pHostent;
	pHostent = gethostbyname(domain.c_str());
	//gethostbyname()���ض�Ӧ�ڸ����������İ����������ֺ͵�ַ��Ϣ��hostent�ṹ��ָ�롣�õ��й�����������Ϣ

	addrSrv.sin_addr.S_un.S_addr = *((DWORD *)pHostent->h_addr_list[0]);    //�õ�smtp�������������ֽ����ip��ַ   
	addrSrv.sin_family = AF_INET;
	addrSrv.sin_port = htons(port);  /* short, network byte order */
									 /*
									 �������뽫 short �ӱ����ֽ�˳��ת ��Ϊ�����ֽ�˳���� "h" ��ʾ "���� (host)"��
									 ������ "to"��Ȼ���� "n" �� ʾ "���� (network)"��
									 ����� "s" ��ʾ "short"�� h-to-n-s, ���� htons() ("Host to Network Short")��
									 https://www.cnblogs.com/kefeiGame/p/7246942.html

									 Ϊʲô�����ݽṹ struct sockaddr_in �У� sin_addr �� sin_port ��Ҫת��Ϊ�����ֽ�˳��
									 ��sin_family �費��Ҫ��? ���ǣ� sin_addr �� sin_port �ֱ��װ�ڰ��� IP �� UDP �㡣
									 ��ˣ����Ǳ���Ҫ �������ֽ�˳�򡣵��� sin_family ��ֻ�Ǳ��ں� (kernel) ʹ������������ �ݽṹ�а���ʲô���͵ĵ�ַ��
									 �����������Ǳ����ֽ�˳��ͬʱ�� sin_family û�з��͵������ϣ����ǿ����Ǳ����ֽ�˳��
									 */


	int err = connect(sockClient, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));   //��������������� 
																			//int connect(int sockfd, struct sockaddr *serv_addr, int addrlen);

	if (err != 0)
	{							// don't forget to error check the connect()! 
		return false;
		//printf("����ʧ��\n");
	}
	this->sockClient = sockClient;
	if (false == Recv())
	{
		return false;
	}
	return true;
}

bool CSmtp::Send(std::string &message)
{
	int err = send(sockClient, message.c_str(), message.length(), 0);
	/*const char *c_str()const;//����һ����null��ֹ��c�ַ���
	c_str()��������һ��ָ������c�ַ�����ָ��,���ݺ�string��ı��������һ����,
	ͨ��string���c_str()�����ܹ���string����ת����c�е��ַ�������ʽ;*/
	if (err == SOCKET_ERROR)
	{
		return false;
	}
	std::string message01;
	return true;
}


bool CSmtp::Recv()
{
	memset(buff, 0, sizeof(char)* (MAXLEN + 1));  //���ͻ����������ʼ��
	int err = recv(sockClient, buff, MAXLEN, 0); //��������
												 //int recv( _In_ SOCKET s, _Out_ char *buf, _In_ int len, _In_ int flags);

												 /*
												 recv�ȵȴ�s�ķ��ͻ����е����ݱ�Э�鴫����ϣ�
												 ���Э���ڴ���s�ķ��ͻ����е�����ʱ�������������ôrecv��������SOCKET_ERROR��
												 ���s�ķ��ͻ�����û�����ݻ������ݱ�Э��ɹ�������Ϻ�recv�ȼ���׽���s�Ľ��ջ�������
												 ���s���ջ�������û�����ݻ���Э�����ڽ������ݣ���ôrecv��һֱ�ȴ���ֱ��Э������ݽ�����ϡ�
												 ��Э������ݽ�����ϣ�recv�����Ͱ�s�Ľ��ջ����е�����copy��buf��
												 ��ע��Э����յ������ݿ��ܴ���buf�ĳ��ȣ����������������Ҫ���ü���recv�������ܰ�s�Ľ��ջ����е�����copy�ꡣ
												 recv����������copy���ݣ������Ľ���������Э������ɵģ���
												 */

	if (err == SOCKET_ERROR)
	{
		return false;
	}
	buff[err] = '\0';  //ecv����������ʵ��copy���ֽ��������Կ��Գ�ʼ��
	return true;
}


int CSmtp::Login()
{
	std::string sendBuff;
	sendBuff = "HELO ";
	sendBuff += user; // ��һ������Ҫͨ��telnet��֤һ��
	sendBuff += "\r\n";

	if (false == Send(sendBuff) || false == Recv()) //�Ȳ�����Ҳ������
	{
		return 1; /*1��ʾ����ʧ�������������*/
	}

	sendBuff.empty();  //���
	sendBuff = "AUTH LOGIN\r\n";
	if (false == Send(sendBuff) || false == Recv()) //�����½
	{
		return 1; /*1��ʾ����ʧ�������������*/
	}

	sendBuff.empty();
	int pos = user.find('@', 0);   //��λ��0��ʼ�����ַ�
								   //string���Һ�������Ψһ�ķ������ͣ��Ǿ���size_type����һ���޷��������������ҳɹ������ذ����ҹ����ҵ��ĵ�һ���ַ����Ӵ���λ�ã�������ʧ�ܣ�����npos����-1����ӡ����Ϊ4294967295����
	sendBuff = user.substr(0, pos); //�õ��û���
	char *ecode;

	/*������˳����һ�䣬����string���length������C�����е�strlen����������,strlen��������ĳ��ȣ�
	ֻ��'\0'�ַ�Ϊֹ,��string::length()����ʵ���Ϸ��ص���string�����ַ�����Ĵ�С,���Լ����Բ���һ�£�
	��Ҳ��Ϊʲô�����治ʹ��string::length()��ԭ��*/

	ecode = base64Encode(sendBuff.c_str(), strlen(sendBuff.c_str()));
	sendBuff.empty();
	sendBuff = ecode;
	sendBuff += "\r\n";
	delete[]ecode;
	//delete �� delete []���������� https://www.cnblogs.com/wangjian8888/p/7905176.html

	if (false == Send(sendBuff) || false == Recv()) //�����û����������շ������ķ���
	{
		return 1; /*������1��ʾ����ʧ�������������*/
	}

	sendBuff.empty();
	ecode = base64Encode(pass.c_str(), strlen(pass.c_str()));
	sendBuff = ecode;
	sendBuff += "\r\n";
	delete[]ecode;

	if (false == Send(sendBuff) || false == Recv()) //�����û����룬�����շ������ķ���
	{
		return 1; /*������1��ʾ����ʧ�������������*/
	}


	if (NULL != strstr(buff, "550"))
	{
		return 2;/*������2��ʾ�û�������*/
	}

	if (NULL != strstr(buff, "535")) /*535����֤ʧ�ܵķ���*/
	{
		return 3; /*������3��ʾ�������*/
	}
	return 0;
}



bool CSmtp::SendEmailHead()     //�����ʼ�ͷ����Ϣ
{
	std::string sendBuff;
	sendBuff = "MAIL FROM: <" + user + ">\r\n";
	if (false == Send(sendBuff) || false == Recv())
	{
		return false; /*��ʾ����ʧ�������������*/
	}

	std::istringstream is(targetAddr);
	//istringstream��ô�� https://zhidao.baidu.com/question/366022043.html
	/*
	istringstream��C++�����һ��������������࣬�����Դ���һ������
	Ȼ���������Ϳ��԰�һ���ַ�����Ȼ���Կո�Ϊ�ָ����Ѹ��зָ�������
	*/


	std::string tmpadd;
	while (is >> tmpadd)
	{
		sendBuff.empty();
		sendBuff = "RCPT TO: <" + tmpadd + ">\r\n";
		if (false == Send(sendBuff) || false == Recv())
		{
			return false; /*��ʾ����ʧ�������������*/
		}
	}

	sendBuff.empty();
	sendBuff = "DATA\r\n";
	if (false == Send(sendBuff) || false == Recv())
	{
		return false; //��ʾ����ʧ�������������
	}

	sendBuff.empty();
	FormatEmailHead(sendBuff);
	if (false == Send(sendBuff))
		//������ͷ��֮�󲻱ص��ý��պ���,��Ϊ��û��\r\n.\r\n��β����������Ϊ��û�з������ݣ����Բ��᷵��ʲôֵ
	{
		return false; /*��ʾ����ʧ�������������*/
	}
	return true;
}



void CSmtp::FormatEmailHead(std::string &email)
{/*��ʽ��Ҫ���͵�����*/
	email = "From: ";
	email += user;
	email += "\r\n";
	email += "To: ";
	email += targetAddr;
	email += "\r\n";
	email += "Subject: ";
	email += title;
	email += "\r\n";
	email += "MIME-Version: 1.0";
	email += "\r\n";
	email += "Content-Type: multipart/mixed;boundary=qwertyuiop";
	email += "\r\n";
	email += "\r\n";
}


bool CSmtp::SendTextBody()  /*�����ʼ��ı�*/
{
	std::string sendBuff;
	sendBuff = "--qwertyuiop\r\n";
	sendBuff += "Content-Type: text/plain;";
	sendBuff += "charset=\"gb2312\"\r\n\r\n";
	sendBuff += content;
	sendBuff += "\r\n\r\n";
	return Send(sendBuff);
}


int CSmtp::SendAttachment_Ex() /*���͸���*/
{
	for (std::list<FILEINFO *>::iterator pIter = listFile.begin(); pIter != listFile.end(); pIter++)
	{
		//cout << "Attachment is sending ~~~~~" << endl;
		//cout << "Please be patient!" << endl;
		std::string sendBuff;
		sendBuff = "--qwertyuiop\r\n";
		sendBuff += "Content-Type: application/octet-stream;\r\n";
		sendBuff += " name=\"";
		sendBuff += (*pIter)->fileName;
		sendBuff += "\"";
		sendBuff += "\r\n";
		sendBuff += "Content-Transfer-Encoding: base64\r\n";
		sendBuff += "Content-Disposition: attachment;\r\n";
		sendBuff += " filename=\"";
		sendBuff += (*pIter)->fileName;
		sendBuff += "\"";
		sendBuff += "\r\n";
		sendBuff += "\r\n";
		Send(sendBuff);
		std::ifstream ifs((*pIter)->filePath, std::ios::in | std::ios::binary);
		//ifstream�Ǵ�Ӳ�̵��ڴ棬��ʵ��ν������������ڴ�ռ�;https://www.cnblogs.com/fnlingnzb-learner/p/5960211.html

		/*
		ios::app�������� //��׷�ӵķ�ʽ���ļ�
		ios::ate�������� //�ļ��򿪺�λ���ļ�β��ios:app�Ͱ����д�����
		ios::binary���� //�Զ����Ʒ�ʽ���ļ���ȱʡ�ķ�ʽ���ı���ʽ�����ַ�ʽ�������ǰ��
		ios::in�������� //�ļ������뷽ʽ�򿪣��ļ��������뵽�ڴ棩
		ios::out�������� //�ļ��������ʽ�򿪣��ڴ�����������ļ���
		ios::nocreate�� //�������ļ��������ļ�������ʱ��ʧ��
		ios::noreplace��//�������ļ������Դ��ļ�ʱ����ļ�����ʧ��
		ios::trunc���� //����ļ����ڣ����ļ�������Ϊ0
		*/

		if (false == ifs.is_open())
		{
			return 4; /*������4��ʾ�ļ��򿪴���*/
		}
		char fileBuff[MAX_FILE_LEN];
		char *chSendBuff;
		memset(fileBuff, 0, sizeof(fileBuff));
		/*�ļ�ʹ��base64���ܴ���*/

		while (ifs.read(fileBuff, MAX_FILE_LEN))
			/*
			Ҫ��д���������ݿ飬ʹ�ó�Ա����read()��write()��Ա����������ԭ���£�
			read(unsigned char *buf, int num); ���ļ��ж�ȡ num ���ַ��� buf ָ��Ļ�����
			write(const unsigned char *buf, int num);
			��buf ָ��Ļ���д num ���ַ����ļ��С�ֵ��ע����ǻ���������� unsigned char *
			*/
		{
			//cout << ifs.gcount() << endl;
			chSendBuff = base64Encode(fileBuff, MAX_FILE_LEN);  //base64����
			chSendBuff[strlen(chSendBuff)] = '\r';    //�س�  13   �ص���ǰ�е����ף������ỻ����һ��
			chSendBuff[strlen(chSendBuff)] = '\n';    //����  10   ������ǰλ�õ���һ�У�������ص�����
			send(sockClient, chSendBuff, strlen(chSendBuff), 0);
			delete[]chSendBuff;
		}

		//cout << ifs.gcount() << endl;  �����ó�Ա���� int gcount();��ȡ��ʵ�ʶ�ȡ���ַ���
		chSendBuff = base64Encode(fileBuff, ifs.gcount());
		chSendBuff[strlen(chSendBuff)] = '\r';
		chSendBuff[strlen(chSendBuff)] = '\n';
		int err = send(sockClient, chSendBuff, strlen(chSendBuff), 0);

		if (err != strlen(chSendBuff))
		{
			//cout << "�ļ����ͳ���!" << endl;
			return 1;
		}
		delete[]chSendBuff;
	}
	return 0;
}



int CSmtp::SendEmail_Ex()
{
	if (false == CreateConn())
	{
		return 1;
	}
	//Recv();
	int err = Login(); //�ȵ�¼
	if (err != 0)
	{
		return err; //����������Ҫ����
	}
	if (false == SendEmailHead()) //����EMAILͷ����Ϣ
	{
		return 1; /*������1����������Ĵ���*/
	}

	if (false == SendTextBody())
	{
		return 1; /*������1����������Ĵ���*/
	}
	err = SendAttachment_Ex();
	if (err != 0)
	{
		return err;
	}
	if (false == SendEnd())
	{
		return 1; /*������1����������Ĵ���*/
	}
	return 0; /*0��ʾû�г���*/
}


void CSmtp::AddAttachment(std::string &filePath) //��Ӹ���
{
	FILEINFO *pFile = new FILEINFO;
	strcpy_s(pFile->filePath, filePath.c_str());
	const char *p = filePath.c_str();
	strcpy_s(pFile->fileName, p + filePath.find_last_of("\\") + 1);
	/*
	https://blog.csdn.net/younibugudano/article/details/71223139
	����find_first_of()�� find_last_of() ִ�м򵥵�ģʽƥ�䣬�����ַ����в��ҵ����ַ�c��
	����find_first_of() �������ַ����е�1�����ֵ��ַ�c��
	������find_last_of()�������һ�����ֵ�c��
	ƥ���λ���Ƿ���ֵ�����û��ƥ�䷢������������-1.
	int find_first_of(char c, int start = 0):
	*/

	listFile.push_back(pFile);
}



void CSmtp::DeleteAttachment(std::string &filePath) //ɾ������
{
	std::list<FILEINFO *>::iterator pIter;
	for (pIter = listFile.begin(); pIter != listFile.end(); pIter++)
	{
		if (strcmp((*pIter)->filePath, filePath.c_str()) == 0)  //һ����ɾ��
		{
			FILEINFO *p = *pIter;
			listFile.remove(*pIter);  //listɾ��Ԫ��
			delete p;
			break;
		}
	}
}


void CSmtp::DeleteAllAttachment() /*ɾ�����е��ļ�*/
{
	for (std::list<FILEINFO *>::iterator pIter = listFile.begin(); pIter != listFile.end();)
	{
		FILEINFO *p = *pIter;
		pIter = listFile.erase(pIter);
		delete p;
	}
}


void CSmtp::SetSrvDomain(std::string &domain)
{
	this->domain = domain;
}


void CSmtp::SetUserName(std::string &user)
{
	this->user = user;
}


void CSmtp::SetPass(std::string &pass)
{
	this->pass = pass;
}

void CSmtp::SetTargetEmail(std::string &targetAddr)
{
	this->targetAddr = targetAddr;
}

void CSmtp::SetEmailTitle(std::string &title)
{
	this->title = title;
}

void CSmtp::SetContent(std::string &content)
{
	this->content = content;
}

void CSmtp::SetPort(int port)
{
	this->port = port;
}
