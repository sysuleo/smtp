#ifndef __SMTP_H__ //#ifndef����һ�ֺ궨���жϣ������Ƿ�ֹ���ض��塣#ifndef��if not define�ļ�д��
#define __SMTP_H__

#include<list>
#include<WinSock2.h>
#include<iostream>
#include<fstream>
#include<string>
#include<sstream>

const int MAX_FILE_LEN = 6000;
const int MAXLEN = 1024;

static const char base64Char[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

struct FILEINFO { /*������¼�ļ���һЩ��Ϣ*/
	char fileName[128];
	char filePath[256];
};

class CSmtp {
public:
	CSmtp(void);
	CSmtp(
		int port,
		std::string srvDomain, //smtp����������
		std::string userName, //�û���
		std::string password, //����
		std::string targetEmail,
		std::string emailTitle,
		std::string content
	);
public:
	~CSmtp(void);
public:
	int port;
public:
	std::string domain;
	std::string user;
	std::string pass;
	std::string targetAddr;
	std::string title;
	std::string content;
	std::list<FILEINFO*>listFile;
	/*Ϊ�˷�������ļ���ɾ���ļ�����ģ�ʹ��list������Ϊ���㣬���Ŵ�������ݽṹ���涼ѧ��*/

public:
	char buff[MAXLEN + 1];
	int buffLen;
	SOCKET sockClient; //�ͻ����׽���

public:
	bool CreateConn();//��������
	bool Send(std::string &email); //��ʽҪ���͵��ʼ�ͷ��
	bool Recv();

	void FormatEmailHead(std::string &email);//��ʽ��Ҫ���͵��ʼ�ͷ��
	int Login();
	bool SendEmailHead();       //�����ʼ�ͷ����Ϣ
	bool SendTextBody();        //�����ı���Ϣ
								//bool SendAttachment();        //���͸���
	int SendAttachment_Ex();
	bool SendEnd();

public:
	void AddAttachment(std::string &filePath); //��Ӹ���
	void DeleteAttachment(std::string &filePath); //ɾ������
	void DeleteAllAttachment(); //ɾ�����еĸ���
	void SetSrvDomain(std::string &domain);
	void SetUserName(std::string &user);
	void SetPass(std::string &pass);
	void SetTargetEmail(std::string &targetAddr);  //Ŀ���ַ
	void SetEmailTitle(std::string &title);  //��Ŀ
	void SetContent(std::string &content);  //����
	void SetPort(int port);
	int SendEmail_Ex();
	/*���ڴ������˵��:1.��������µĴ���2.�û�������3.�������4.�ļ�������0.�ɹ�*/
	char* base64Encode(char const* origSigned, unsigned origLength);
};  //class �ӷֺţ����� error C2628: followed by 'char' is illegal (did you forget a ';'?)
#endif // !__SMTP_H__