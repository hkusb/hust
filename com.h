#include <stdio.h>

#include <stdlib.h>

#include <string.h>

#include <netinet/in.h>

#include <math.h>

#define PCAP_FILE "222.pcap"

#define MAX_ETH_FRAME 644235875

#define ERROR_FILE_OPEN_FAILED -1

#define ERROR_MEM_ALLOC_FAILED -2

#define ERROR_PCAP_PARSE_FAILED -3

#define OVERTIME 50 //flow超时时间，单位秒

/****
 * 添加类型定义
 */
 /*
typedef long bpf_int32;
typedef unsigned long bpf_u_int32;
typedef unsigned short  u_short;
*/
/***********end**********/

typedef unsigned long u_int32;
typedef unsigned short u_int16;
typedef unsigned char u_int8;

typedef unsigned int  bpf_u_int32;

typedef unsigned short  u_short;

typedef int bpf_int32;

typedef int elemType ;

//typedef u_int32_t in_addr_t;
/*
struct in_addr
{
	in_addr_t s_addr;
};
 */
/*

 Pcap文件头24B各字段说明：

 Magic：4B：0x1A 2B 3C 4D:用来标示文件的开始

 Major：2B，0x02 00:当前文件主要的版本号

 Minor：2B，0x04 00当前文件次要的版本号

 ThisZone：4B当地的标准时间；全零

 SigFigs：4B时间戳的精度；全零

 SnapLen：4B最大的存储长度

 LinkType：4B链路类型

 常用类型：

 0            BSD loopback devices, except for later OpenBSD

 1            Ethernet, and Linux loopback devices

 6            802.5 Token Ring

 7            ARCnet

 8            SLIP

 9            PPP

 */



typedef struct pcap_file_header pcap_file_header;


/*
 Packet 包头和Packet数据组成

 字段说明：

 Timestamp：时间戳高位，精确到seconds

 Timestamp：时间戳低位，精确到microseconds

 Caplen：当前数据区的长度，即抓取到的数据帧长度，由此可以得到下一个数据帧的位置。

 Len：离线数据长度：网络中实际数据帧的长度，一般不大于caplen，多数情况下和Caplen数值相等。

 Packet 数据：即 Packet（通常就是链路层的数据帧）具体内容，长度就是Caplen，这个长度的后面，就是当前PCAP文件中存放的下一个Packet数据包，也就 是说：PCAP文件里面并没有规

定捕获的Packet数据包之间有什么间隔字符串，下一组数据在文件中的起始位置。我们需要靠第一个Packet包确定。

 */

typedef struct  timestamp
{

	bpf_u_int32 timestamp_s;

	bpf_u_int32 timestamp_ms;

}
timestamp;

struct time_diff
{
	double time;
	struct time_diff *next;
};

struct time_diff_fetures
{
    double min;
    double max;
    double mean;
    double sd;
};

typedef struct pcap_header
{

	timestamp ts;

	bpf_u_int32 capture_len;

	bpf_u_int32 len;


}pcap_header;

/********************************************/
/*
 关于网络包数据结构的定义
 */
 //数据帧头
typedef struct FramHeader_t
{ //Pcap捕获的数据帧头
u_int8 DstMAC[6]; //目的MAC地址
u_int8 SrcMAC[6]; //源MAC地址
u_short FrameType;    //帧类型
} FramHeader_t;
//IP数据报头
typedef struct IPHeader_t
{ //IP数据报头
u_int8 Ver_HLen;       //版本+报头长度
u_int8 TOS;            //服务类型
u_int16 TotalLen;       //总长度
u_int16 ID; //标识
u_int16 Flag_Segment;   //标志+片偏移
u_int8 TTL;            //生存周期
u_int8 Protocol;       //协议类型
u_int16 Checksum;       //头部校验和
//struct in_addr SrcIP; //源IP地址
//struct in_addr DstIP; //目的IP地址
u_int32_t SrcIP; //源IP地址
u_int32_t DstIP; //目的IP地址
} IPHeader_t;
//TCP数据报头
typedef struct TCPHeader_t
{ //TCP数据报头
u_int16 SrcPort; //源端口
u_int16 DstPort; //目的端口
u_int32 SeqNO; //序号
u_int32 AckNO; //确认号
u_int8 HeaderLen; //数据报头的长度(4 bit) + 保留(4 bit)
u_int8 Flags; //标识TCP不同的控制消息
u_int16 Window; //窗口大小
u_int16 Checksum; //校验和
u_int16 UrgentPointer;  //紧急指针
}TCPHeader_t;

typedef struct Flow
{
//struct in_addr SrcIP; //源IP地址
//struct in_addr DstIP; //目的IP地址
u_int32_t SrcIP; //源IP地址
u_int32_t DstIP; //目的IP地址
u_int16 SrcPort; //源端口
u_int16 DstPort; //目的端口
u_int8 Protocol;       //协议类型
}Flow;

typedef struct ListInfo
{
	struct pcap_header time_len;
	struct ListInfo *next;
}ListInfo;
/************************************************************************/
typedef struct Node{    /* 定义单链表结点类型 */
    struct Flow flow;
    struct ListInfo *cs;//cs方向
    struct ListInfo *sc;//sc方向
    struct timestamp flow_begin_time;  //flow开始时间戳，用于判断超时
    int cs_packets;      //cs方向数据包个数
    int sc_packets;      //sc方向数据包个数
    int cs_bytes;		 //cs方向bytes数
    int sc_bytes;		 //sc方向bytes数
    int cs_packet_size_min; //cs方向数据包大小的最小值
    int cs_packet_size_max; //cs方向数据包大小的最大值
    double cs_packet_size_mean;//cs方向数据包大小的平均值
    double cs_packet_size_sd;  //cs方向数据包大小的标准差
    int sc_packet_size_min; //sc方向数据包大小的最小值
    int sc_packet_size_max; //sc方向数据包大小的最大值
    double sc_packet_size_mean;//sc方向数据包大小的平均值
    double sc_packet_size_sd;  //sc方向数据包大小的标准差
    struct time_diff *cs_time;
    struct time_diff *sc_time;
    struct time_diff_fetures cs_tdf;
    struct time_diff_fetures sc_tdf;
    int flag;				//标志该流的特征是否已提取，-1表示已提取
    struct Node *next;
}Node;
/***数据包结构定义完成****/


void prinfPcapFileHeader(pcap_file_header *pfh);

void printfPcapHeader(pcap_header *ph);
void printPcap(void * data,size_t size,pcap_header *ph);
void initList(Node **pNode);
int insertLastList(Node **pNode,Flow insertElem,pcap_header *ph);
void printList(Node *pHead);
