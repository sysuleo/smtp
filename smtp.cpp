// build-up-mstp.cpp : Defines the entry point for the console application.
//


#include "smtp.h"
#include <iostream>
#include <fstream>

using namespace std;

#pragma  comment(lib, "ws2_32.lib") /*链接ws2_32.lib动态链接库*/
/* 类似于opencv一样，要添加链接库函数，cv.lib等，要添加到附加依赖项，
或者通过#pragma comment（lib, ”cv.lib“）一样，然后才能包含头文件进行各种函数的调用
*socket编程要调用各种socket函数，但是需要库Ws2_32.lib和头文件Winsock2.h*/

/*base64采用别人的编码,不过，这不是重点，重点是我完成了我的一个比较好的邮件发送客户端*/

char* CSmtp::base64Encode(char const* origSigned, unsigned origLength) {
	unsigned char const* orig = (unsigned char const*)origSigned; // in case any input bytes have the MSB set
	if (orig == NULL) return NULL;

	unsigned const numOrig24BitValues = origLength / 3;
	bool havePadding = origLength > numOrig24BitValues * 3;  //origLength不是3的倍数
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



CSmtp::CSmtp(void)  //默认构造函数
{
	this->content = "";
	this->port = 25;
	this->user = "";
	this->pass = "";
	this->targetAddr = "";
	this->title = "";
	this->domain = "";

	WORD wVersionRequested;  //不是C++标准的类型，是微软SDK中的类型，WORD的意思为字，是2byte的无符号整数，表示范围0~65535. 
	WSADATA wsaData;
	//WSADATA，一种数据结构。这个结构被用来存储被WSAStartup函数调用后返回的Windows Sockets数据。它包含Winsock.dll执行的数据


	/*　　结构原型：　　
	struct WSAData {
	　　WORD wVersion;  高位字节存储副版本号, 低位字节存储主版本号，可以用WORD MAKEWORD(BYTE,BYTE ) 返回这个值,例如:MAKEWORD(1,1)
	  　　WORD wHighVersion;  这个DLL能够支持的Windows Sockets规范的最高版本。通常它与wVersion相同。
		　　char szDescription[WSADESCRIPTION_LEN+1]; 以null结尾的ASCII字符串，Windows Sockets DLL将对Windows Sockets实现的描述拷贝到这个字符串中，包括制造商标识。
		  　　char szSystemStatus[WSASYSSTATUS_LEN+1]; 以null结尾的ASCII字符串，Windows Sockets DLL把有关的状态或配置信息拷贝到该字符串中。Windows Sockets DLL应当仅在这些信息对用户或支持人员有用时才使用它们，它不应被作为szDescription域的扩展。
			　　unsigned short iMaxSockets;  单个进程能够打开的socket的最大数目
			  　　unsigned short iMaxUdpDg;  能够发送或接收的最大的用户数据包协议（UDP）的数据包大小，以字节为单位。如果实现方式没有限制，那么iMaxUdpDg为零。
				　　char *lpVendorInfo;}; 指向销售商的数据结构的指针。这个结构的定义（如果有）超出了WindowsSockets规范的范围。WinSock2.0版中已被废弃。
				  */


	int err;
	//makeword是将两个byte型合并成一个word型，一个在高8位(b)，一个在低8位(a)  00000001 00000010
	//程序要使用2.1版本的Socket,那么程序代码如下两行
	wVersionRequested = MAKEWORD(2, 1);

	/*这里的WSAStartup就是为了向操作系统说明，我们要用哪个库文件，
	让该库文件与当前的应用程序绑定，从而就可以调用该版本的socket的各种函数了。*/
	err = WSAStartup(wVersionRequested, &wsaData);
	this->sockClient = 0;
}


CSmtp::~CSmtp(void)  //析构函数
{
	DeleteAllAttachment();
	closesocket(sockClient);
	WSACleanup();
	/*
	int WSACleanup (void);
	应用程序在完成对请求的Socket库的使用后，
	要调用WSACleanup函数来解除与Socket库的绑定并且释放Socket库所占用的系统资源。
	*/
}

CSmtp::CSmtp(   //构造函数
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
	//为建立socket对象做准备，初始化环境
	SOCKET sockClient = socket(AF_INET, SOCK_STREAM, 0); //建立socket对象    /* 错误检查 */
														 //int socket(int domain, int type, int protocol);

	SOCKADDR_IN addrSrv;

	/*
	struct sockaddr_in {
	short int sin_family;       通信类型
	unsigned short int sin_port;    端口
	struct in_addr sin_addr;     Internet 地址
	unsigned char sin_zero[8];    与sockaddr结构的长度相同
	};
	*/

	HOSTENT* pHostent;
	pHostent = gethostbyname(domain.c_str());
	//gethostbyname()返回对应于给定主机名的包含主机名字和地址信息的hostent结构的指针。得到有关于域名的信息

	addrSrv.sin_addr.S_un.S_addr = *((DWORD *)pHostent->h_addr_list[0]);    //得到smtp服务器的网络字节序的ip地址   
	addrSrv.sin_family = AF_INET;
	addrSrv.sin_port = htons(port);  /* short, network byte order */
									 /*
									 假设你想将 short 从本机字节顺序转 换为网络字节顺序。用 "h" 表示 "本机 (host)"，
									 接着是 "to"，然后用 "n" 表 示 "网络 (network)"，
									 最后用 "s" 表示 "short"： h-to-n-s, 或者 htons() ("Host to Network Short")。
									 https://www.cnblogs.com/kefeiGame/p/7246942.html

									 为什么在数据结构 struct sockaddr_in 中， sin_addr 和 sin_port 需要转换为网络字节顺序，
									 而sin_family 需不需要呢? 答案是： sin_addr 和 sin_port 分别封装在包的 IP 和 UDP 层。
									 因此，它们必须要 是网络字节顺序。但是 sin_family 域只是被内核 (kernel) 使用来决定在数 据结构中包含什么类型的地址，
									 所以它必须是本机字节顺序。同时， sin_family 没有发送到网络上，它们可以是本机字节顺序。
									 */


	int err = connect(sockClient, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));   //向服务器发送请求 
																			//int connect(int sockfd, struct sockaddr *serv_addr, int addrlen);

	if (err != 0)
	{							// don't forget to error check the connect()! 
		return false;
		//printf("链接失败\n");
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
	/*const char *c_str()const;//返回一个以null终止的c字符串
	c_str()函数返回一个指向正规c字符串的指针,内容和string类的本身对象是一样的,
	通过string类的c_str()函数能够把string对象转换成c中的字符串的样式;*/
	if (err == SOCKET_ERROR)
	{
		return false;
	}
	std::string message01;
	return true;
}


bool CSmtp::Recv()
{
	memset(buff, 0, sizeof(char)* (MAXLEN + 1));  //发送缓冲区用零初始化
	int err = recv(sockClient, buff, MAXLEN, 0); //接收数据
												 //int recv( _In_ SOCKET s, _Out_ char *buf, _In_ int len, _In_ int flags);

												 /*
												 recv先等待s的发送缓冲中的数据被协议传送完毕，
												 如果协议在传送s的发送缓冲中的数据时出现网络错误，那么recv函数返回SOCKET_ERROR；
												 如果s的发送缓冲中没有数据或者数据被协议成功发送完毕后，recv先检查套接字s的接收缓冲区，
												 如果s接收缓冲区中没有数据或者协议正在接收数据，那么recv就一直等待，直到协议把数据接收完毕。
												 当协议把数据接收完毕，recv函数就把s的接收缓冲中的数据copy到buf中
												 （注意协议接收到的数据可能大于buf的长度，所以在这种情况下要调用几次recv函数才能把s的接收缓冲中的数据copy完。
												 recv函数仅仅是copy数据，真正的接收数据是协议来完成的）；
												 */

	if (err == SOCKET_ERROR)
	{
		return false;
	}
	buff[err] = '\0';  //ecv函数返回其实际copy的字节数。所以可以初始化
	return true;
}


int CSmtp::Login()
{
	std::string sendBuff;
	sendBuff = "HELO ";
	sendBuff += user; // 这一部分需要通过telnet验证一下
	sendBuff += "\r\n";

	if (false == Send(sendBuff) || false == Recv()) //既不接收也不发送
	{
		return 1; /*1表示发送失败由于网络错误*/
	}

	sendBuff.empty();  //清空
	sendBuff = "AUTH LOGIN\r\n";
	if (false == Send(sendBuff) || false == Recv()) //请求登陆
	{
		return 1; /*1表示发送失败由于网络错误*/
	}

	sendBuff.empty();
	int pos = user.find('@', 0);   //从位置0开始查找字符
								   //string查找函数都有唯一的返回类型，那就是size_type，即一个无符号整数。若查找成功，返回按查找规则找到的第一个字符或子串的位置；若查找失败，返回npos，即-1（打印出来为4294967295）。
	sendBuff = user.substr(0, pos); //得到用户名
	char *ecode;

	/*在这里顺带扯一句，关于string类的length函数与C语言中的strlen函数的区别,strlen计算出来的长度，
	只到'\0'字符为止,而string::length()函数实际上返回的是string类中字符数组的大小,你自己可以测试一下，
	这也是为什么我下面不使用string::length()的原因*/

	ecode = base64Encode(sendBuff.c_str(), strlen(sendBuff.c_str()));
	sendBuff.empty();
	sendBuff = ecode;
	sendBuff += "\r\n";
	delete[]ecode;
	//delete 和 delete []的真正区别 https://www.cnblogs.com/wangjian8888/p/7905176.html

	if (false == Send(sendBuff) || false == Recv()) //发送用户名，并接收服务器的返回
	{
		return 1; /*错误码1表示发送失败由于网络错误*/
	}

	sendBuff.empty();
	ecode = base64Encode(pass.c_str(), strlen(pass.c_str()));
	sendBuff = ecode;
	sendBuff += "\r\n";
	delete[]ecode;

	if (false == Send(sendBuff) || false == Recv()) //发送用户密码，并接收服务器的返回
	{
		return 1; /*错误码1表示发送失败由于网络错误*/
	}


	if (NULL != strstr(buff, "550"))
	{
		return 2;/*错误码2表示用户名错误*/
	}

	if (NULL != strstr(buff, "535")) /*535是认证失败的返回*/
	{
		return 3; /*错误码3表示密码错误*/
	}
	return 0;
}



bool CSmtp::SendEmailHead()     //发送邮件头部信息
{
	std::string sendBuff;
	sendBuff = "MAIL FROM: <" + user + ">\r\n";
	if (false == Send(sendBuff) || false == Recv())
	{
		return false; /*表示发送失败由于网络错误*/
	}

	std::istringstream is(targetAddr);
	//istringstream怎么用 https://zhidao.baidu.com/question/366022043.html
	/*
	istringstream是C++里面的一种输入输出控制类，它可以创建一个对象，
	然后这个对象就可以绑定一行字符串，然后以空格为分隔符把该行分隔开来。
	*/


	std::string tmpadd;
	while (is >> tmpadd)
	{
		sendBuff.empty();
		sendBuff = "RCPT TO: <" + tmpadd + ">\r\n";
		if (false == Send(sendBuff) || false == Recv())
		{
			return false; /*表示发送失败由于网络错误*/
		}
	}

	sendBuff.empty();
	sendBuff = "DATA\r\n";
	if (false == Send(sendBuff) || false == Recv())
	{
		return false; //表示发送失败由于网络错误
	}

	sendBuff.empty();
	FormatEmailHead(sendBuff);
	if (false == Send(sendBuff))
		//发送完头部之后不必调用接收函数,因为你没有\r\n.\r\n结尾，服务器认为你没有发完数据，所以不会返回什么值
	{
		return false; /*表示发送失败由于网络错误*/
	}
	return true;
}



void CSmtp::FormatEmailHead(std::string &email)
{/*格式化要发送的内容*/
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


bool CSmtp::SendTextBody()  /*发送邮件文本*/
{
	std::string sendBuff;
	sendBuff = "--qwertyuiop\r\n";
	sendBuff += "Content-Type: text/plain;";
	sendBuff += "charset=\"gb2312\"\r\n\r\n";
	sendBuff += content;
	sendBuff += "\r\n\r\n";
	return Send(sendBuff);
}


int CSmtp::SendAttachment_Ex() /*发送附件*/
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
		//ifstream是从硬盘到内存，其实所谓的流缓冲就是内存空间;https://www.cnblogs.com/fnlingnzb-learner/p/5960211.html

		/*
		ios::app：　　　 //以追加的方式打开文件
		ios::ate：　　　 //文件打开后定位到文件尾，ios:app就包含有此属性
		ios::binary：　 //以二进制方式打开文件，缺省的方式是文本方式。两种方式的区别见前文
		ios::in：　　　 //文件以输入方式打开（文件数据输入到内存）
		ios::out：　　　 //文件以输出方式打开（内存数据输出到文件）
		ios::nocreate： //不建立文件，所以文件不存在时打开失败
		ios::noreplace：//不覆盖文件，所以打开文件时如果文件存在失败
		ios::trunc：　 //如果文件存在，把文件长度设为0
		*/

		if (false == ifs.is_open())
		{
			return 4; /*错误码4表示文件打开错误*/
		}
		char fileBuff[MAX_FILE_LEN];
		char *chSendBuff;
		memset(fileBuff, 0, sizeof(fileBuff));
		/*文件使用base64加密传送*/

		while (ifs.read(fileBuff, MAX_FILE_LEN))
			/*
			要读写二进制数据块，使用成员函数read()和write()成员函数，它们原型下：
			read(unsigned char *buf, int num); 从文件中读取 num 个字符到 buf 指向的缓存中
			write(const unsigned char *buf, int num);
			从buf 指向的缓存写 num 个字符到文件中。值得注意的是缓存的类型是 unsigned char *
			*/
		{
			//cout << ifs.gcount() << endl;
			chSendBuff = base64Encode(fileBuff, MAX_FILE_LEN);  //base64加密
			chSendBuff[strlen(chSendBuff)] = '\r';    //回车  13   回到当前行的行首，而不会换到下一行
			chSendBuff[strlen(chSendBuff)] = '\n';    //换行  10   换到当前位置的下一行，而不会回到行首
			send(sockClient, chSendBuff, strlen(chSendBuff), 0);
			delete[]chSendBuff;
		}

		//cout << ifs.gcount() << endl;  可以用成员函数 int gcount();来取得实际读取的字符数
		chSendBuff = base64Encode(fileBuff, ifs.gcount());
		chSendBuff[strlen(chSendBuff)] = '\r';
		chSendBuff[strlen(chSendBuff)] = '\n';
		int err = send(sockClient, chSendBuff, strlen(chSendBuff), 0);

		if (err != strlen(chSendBuff))
		{
			//cout << "文件传送出错!" << endl;
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
	int err = Login(); //先登录
	if (err != 0)
	{
		return err; //错误代码必须要返回
	}
	if (false == SendEmailHead()) //发送EMAIL头部信息
	{
		return 1; /*错误码1是由于网络的错误*/
	}

	if (false == SendTextBody())
	{
		return 1; /*错误码1是由于网络的错误*/
	}
	err = SendAttachment_Ex();
	if (err != 0)
	{
		return err;
	}
	if (false == SendEnd())
	{
		return 1; /*错误码1是由于网络的错误*/
	}
	return 0; /*0表示没有出错*/
}


void CSmtp::AddAttachment(std::string &filePath) //添加附件
{
	FILEINFO *pFile = new FILEINFO;
	strcpy_s(pFile->filePath, filePath.c_str());
	const char *p = filePath.c_str();
	strcpy_s(pFile->fileName, p + filePath.find_last_of("\\") + 1);
	/*
	https://blog.csdn.net/younibugudano/article/details/71223139
	函数find_first_of()和 find_last_of() 执行简单的模式匹配，如在字符串中查找单个字符c。
	函数find_first_of() 查找在字符串中第1个出现的字符c，
	而函数find_last_of()查找最后一个出现的c。
	匹配的位置是返回值。如果没有匹配发生，则函数返回-1.
	int find_first_of(char c, int start = 0):
	*/

	listFile.push_back(pFile);
}



void CSmtp::DeleteAttachment(std::string &filePath) //删除附件
{
	std::list<FILEINFO *>::iterator pIter;
	for (pIter = listFile.begin(); pIter != listFile.end(); pIter++)
	{
		if (strcmp((*pIter)->filePath, filePath.c_str()) == 0)  //一样则删除
		{
			FILEINFO *p = *pIter;
			listFile.remove(*pIter);  //list删除元素
			delete p;
			break;
		}
	}
}


void CSmtp::DeleteAllAttachment() /*删除所有的文件*/
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
