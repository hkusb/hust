#include "com.h"

/* 初始化线性表，即置单链表的表头指针为空 */
void initList(Node **pNode)
{
    *pNode = NULL;
    printf("initList函数执行，初始化成功\n");
}
/*查找是否存在某一个元素******/
int findflow(Node  *pHead,Flow findElem,pcap_header *ph)
{
		//printfPcapHeader(ph);//测试打印
	    if(NULL == pHead)   //链表为空
    {
        printf("查找链表为空\n");
        return 0;
    }
    
    else
    {
        while(NULL != pHead)
        {
		if(pHead->flow.SrcIP==findElem.SrcIP
		&&pHead->flow.DstIP==findElem.DstIP
		&&pHead->flow.SrcPort==findElem.SrcPort
		&&pHead->flow.DstPort==findElem.DstPort
		&&pHead->flow.Protocol==findElem.Protocol
		)
		{
			puts("cs方向流来了一个");
		    ListInfo *newInfo;
		    newInfo = (ListInfo *)malloc(sizeof(ListInfo));
			newInfo->time_len.ts=ph->ts;
			newInfo->time_len.len=ph->len;
			
			newInfo->next=pHead->cs;
			pHead->cs=newInfo;
			pHead->cs_packets += 1;
			pHead->cs_bytes += ph->len;
		 // pHead->cs.time_len.ts=ph->ts;
		  //pHead->cs.time_len.len=ph->len;
		  return 1;//找到cs方向数据
    	}
		else if(pHead->flow.SrcIP==findElem.DstIP
		&&pHead->flow.DstIP==findElem.SrcIP
		&&pHead->flow.SrcPort==findElem.DstPort
		&&pHead->flow.DstPort==findElem.SrcPort
		&&pHead->flow.Protocol==findElem.Protocol)
		{
		    ListInfo *newInfo;
		    newInfo = (ListInfo *)malloc(sizeof(ListInfo));
			newInfo->time_len.ts=ph->ts;
			newInfo->time_len.len=ph->len;
			newInfo->next = pHead->sc;
			pHead->sc = newInfo;
			pHead->sc_packets += 1;
			pHead->sc_bytes += ph->len;
		/*	if(pHead->sc.next==NULL)
			{
			pHead->sc=*newInfo;
			newInfo->next=NULL;
			pHead->sc_packets += 1;
			pHead->sc_bytes += ph->len;
		    }
		    else
		    {
		    newInfo->next=&(pHead->sc);
			pHead->sc=*newInfo;
			pHead->sc_packets += 1;
			pHead->sc_bytes += ph->len;	
			}	
         return 2;//找到sc方向数据
	    }
	    */
		 pHead = pHead->next;
	}
	    return 0;//没找到
	}
}
/* 向单链表的表头添加一个元素 */
int insertLastList(Node **pNode,Flow insertElem,pcap_header *ph)
{
    Node *pInsert;
    pInsert = (Node *)malloc(sizeof(Node)); //申请一个新节点
    memset(pInsert,0,sizeof(Node));
    pInsert->flow.SrcIP=insertElem.SrcIP;
    pInsert->flow.DstIP = insertElem.DstIP;
    pInsert->flow.SrcPort = insertElem.SrcPort;
    pInsert->flow.DstPort = insertElem.DstPort;
    pInsert->flow.Protocol = insertElem.Protocol;
    pInsert->cs_packets = 1;
    pInsert->cs_bytes = ph->len;
    pInsert->cs = NULL;
    pInsert->sc = NULL;
    ListInfo *newInfo;
    //ListInfo *newInfo1;
    newInfo = (ListInfo *)malloc(sizeof(ListInfo));
   // newInfo1 = (ListInfo *)malloc(sizeof(ListInfo));
	newInfo->time_len.ts=ph->ts;
	newInfo->time_len.len=ph->len;
    //pInsert->cs.next=newInfo;
    //newInfo=&(pInsert->cs);
    //pInsert->sc=newInfo1;
    //newInfo->next=&(pInsert->cs);
   // pInsert->cs=*newInfo;
    newInfo->next = NULL;
    pInsert->cs = newInfo;
    pInsert->next = *pNode;
    *pNode = pInsert;
    printf("\ninsertLastList函数执行，向表头插入元素成功\n");
 
    return 1;
}
 
/* 打印链表，链表的遍历*/
void printList(Node *pHead)
{
    if(NULL == pHead)   //链表为空
    {
        printf("PrintList函数执行，链表为空\n");
    }
    else
    {
        while(NULL != pHead)
        {
            printf("原IP:%s",inet_ntoa((struct in_addr*)(pHead->flow.SrcIP)));
            printf("目的ip:%s",inet_ntoa((struct in_addr*)(pHead->flow.DstIP)));
            printf("原端口:%d",ntohs(pHead->flow.SrcPort));
            printf("目的端口:%d\n",ntohs(pHead->flow.DstPort));
            printf("上层协议:%d\n",ntohs(pHead->flow.Protocol));
            printf("cs方向:%d个packets；%d个bytes\n", pHead->cs_packets, pHead->cs_bytes);
            
            ListInfo *p=pHead->cs;
            while(p!=NULL)
            {
			puts("11");
            printfPcapHeader(&(p->time_len));
            //if(p->next!=NULL)
            //{
            p=p->next;
		  //  }
		  //  else
		  //  break;
            puts("12");
            sleep(1);
		    }
		    
            pHead = pHead->next;
            puts("pHead next");
        }
        printf("\n");
    }
}

void overtime_flow_handler(Node  *pHead, timestamp ts)
{
	int cs_packet_size_min, cs_packet_size_max, cs_packet_size_mean, cs_packet_size_sd;
	int sc_packet_size_min, sc_packet_size_max, sc_packet_size_mean, sc_packet_size_sd;
	ListInfo *p;
	
	if (!pHead)
		return;
	while (pHead)
	{
		//超时，提取该flow的特征
		if (ts.timestamp_s - pHead->flow_begin_time.timestamp_s > OVERTIME)
		{
			cs_packet_size_min = cs_packet_size_max = cs_packet_size_mean = cs_packet_size_sd = 0;
			sc_packet_size_min = sc_packet_size_max = sc_packet_size_mean = sc_packet_size_sd = 0;
			//计算CS方向流包大小的最小值、最大值、平均值、标准差
			for (p = &(pHead->cs); p; p = p->next)
				
		}
		pHead = pHead->next;
	}
}
