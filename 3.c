
#include <pcap.h>

#include <arpa/inet.h>

#include <netinet/in.h>

#include "com.h"

Node *pList=NULL;




void prinfPcapFileHeader(pcap_file_header *pfh){

	if (pfh==NULL) {
		return;

	}

	printf("=====================\n"

		   "magic:0x%0x\n"

		   "version_major:%u\n"

		   "version_minor:%u\n"

		   "thiszone:%d\n"

		   "sigfigs:%u\n"

		   "snaplen:%u\n"

		   "linktype:%u\n"

		   "=====================\n",

		   pfh->magic,

		   pfh->version_major,

		   pfh->version_minor,

		   pfh->thiszone,

		   pfh->sigfigs,

		   pfh->snaplen,

		   pfh->linktype);

}
 

void printfPcapHeader(pcap_header *ph){

	if (ph==NULL) {

		return;

	}
	printf("=====================\n"

		   "ts.timestamp_s:%u\n"

		   "ts.timestamp_ms:%u\n"

		   "capture_len:%u\n"

		   "len:%d\n"

		   "=====================\n",

		   ph->ts.timestamp_s,

		   ph->ts.timestamp_ms,

		   ph->capture_len,

		   ph->len);

}
 

void printPcap(void * data,size_t size,pcap_header *ph){

	unsigned  short iPos = 0;


	if (data==NULL) {

		return;

	}
	
	if (ph==NULL) {

		return;

	}
	
   Flow myflow;
   FramHeader_t *ether;
   IPHeader_t *iph;
   TCPHeader_t *tcph;
   ether=(struct FramHeader_t*)data;
   //不是ipv4，返回
   if (ether->FrameType != 0x0008)
		return;
   iph=(struct IPHeader_t*)(data+14);
   //不是TCP、UDP，返回
   if (iph->Protocol != 6 && iph->Protocol != 17)
		return;
   tcph=(struct TCPHeader_t*)(data+14+(((iph->Ver_HLen) & 0x0F) << 2));
   printf("smac %02x:%02x:%02x:%02x:%02x:%02x\r\n",*(ether->SrcMAC),*(ether->SrcMAC+1),
   *(ether->SrcMAC+2),*(ether->SrcMAC+3),*(ether->SrcMAC+4),*(ether->SrcMAC+5));
   printf("dmac %02x:%02x:%02x:%02x:%02x:%02x\r\n",*(ether->DstMAC),*(ether->DstMAC+1),
   *(ether->DstMAC+2),*(ether->DstMAC+3),*(ether->DstMAC+4),*(ether->DstMAC+5));
   printf("以太网类型:%04x\n",ntohs(ether->FrameType));
   struct in_addr ip;
   ip.s_addr = iph->SrcIP;
   printf("原IP:%s",inet_ntoa(ip));
   ip.s_addr = iph->DstIP;
   printf("目的ip:%s",inet_ntoa(ip));
   myflow.DstIP=iph->DstIP;
   myflow.SrcIP=iph->SrcIP;
   myflow.Protocol=iph->Protocol;
   myflow.DstPort=tcph->DstPort;
   myflow.SrcPort=tcph->SrcPort;
   overtime_flow_handler (pList, ph->ts);
   if(findflow(pList,myflow,ph)==0)//新的流
   {
	  // myflow.cs.time_len.ts=ph->ts;
	   //myflow.cs.time_len.len=ph->len;
   insertLastList(&pList,myflow,ph); 
   }
   /*
      if(findflow(pList,myflow,ph)==1)//CS流
   {
  // insertLastList(&pList,myflow); 
   }
      if(findflow(pList,myflow,ph)==2)//SC流
   {
   //insertLastList(&pList,myflow); 
   }*/
	/*
	for (iPos=0; iPos < size/sizeof(unsigned short); iPos++) {

 
		unsigned short a = ntohs( *((unsigned short *)data + iPos ) );

		if (iPos%8==0) printf("\n");

		if (iPos%4==0) printf(" ");

 
	printf("%04x~",a);
 
	}*/
	 //printList(pList);
	printf("\n============\n");

}


int main (int argc, const char * argv[])

{

 
	printf("sizeof:int %d,unsigned int %d,char %d,unsigned char %d,short:%d,unsigned short:%d\n",

		    sizeof(int),sizeof(unsigned int),sizeof(char),sizeof(unsigned char),sizeof(short),sizeof(unsigned short));

 
	pcap_file_header  pfh;
	pcap_header  ph;

	int count=0;

	void * buff = NULL;

	int readSize=0;

	int ret = 0;


    
    initList(&pList); 
    
	FILE *fp = fopen64(PCAP_FILE, "rw");

 
	if (fp==NULL) {

		fprintf(stderr, "Open file %s error.\n",PCAP_FILE);

		ret = ERROR_FILE_OPEN_FAILED;
		
		printf("%d\n",ret);

		goto ERROR;

	}


    //文件已读到fp中。
     fread(&pfh, sizeof(pcap_file_header), 1, fp);
	prinfPcapFileHeader(&pfh);
  // fseek(fp,96,SEEK_SET);
	buff = (void *)malloc(MAX_ETH_FRAME);

	for (count=1;count; count++) 
	{

		memset(buff,0,MAX_ETH_FRAME);

		//read pcap header to get a packet

		//get only a pcap head count .

		readSize=fread(&ph, sizeof(pcap_header), 1, fp);
		

		if (readSize<=0) {

			break;

		}

		//printfPcapHeader(&ph);

 
 
		if (buff==NULL) {
			fprintf(stderr, "malloc memory failed.\n");

			ret = ERROR_MEM_ALLOC_FAILED;

			goto ERROR;

		}

 
		//get a packet contents.

		//read ph.capture_len bytes.
        //fseek(fp,sizeof(pcap_header),SEEK_CUR);
        if(ph.capture_len>2000||ph.capture_len<0)
         {
			 puts("warning.....");
			 sleep(5);
		 }
		readSize=fread(buff,1,ph.capture_len, fp);
		
//		if (readSize != ph.capture_len) {
		if (readSize < 0) {

			free(buff);

			fprintf(stderr, "pcap file parse error:%d\t%d\n", readSize, ph.capture_len);

			ret = ERROR_PCAP_PARSE_FAILED;

			goto ERROR;

		}
		
		printPcap(buff, readSize,&ph);
       // sleep(5000);
 
 
		printf("===count:%d,readSize:%d===\n",count,readSize);

 
		if (feof(fp) || readSize <=0 ) {
 
			break;

		}

       

	}

 
ERROR:

	//free

	if (buff) {

		free(buff);

		buff=NULL;

	} 
	if (fp) {

		fclose(fp);

		fp=NULL;

	}

	
 
    return ret;

}
