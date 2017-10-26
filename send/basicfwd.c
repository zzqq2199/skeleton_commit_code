/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2015 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <stdio.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_common.h>
#include <rte_byteorder.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#define RX_RING_SIZE 128
#define TX_RING_SIZE 512

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

static const struct rte_eth_conf port_conf_default = {
	.rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN }
};

/* basicfwd.c: Basic DPDK skeleton forwarding example. */

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int
port_init(uint8_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 1;
	int retval;
	uint16_t q;

	if (port >= rte_eth_dev_count())
		return -1;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct ether_addr addr;
	rte_eth_macaddr_get(port, &addr);
	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			(unsigned)port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	rte_eth_promiscuous_enable(port);

	return 0;
}

static unsigned short 
checksum(unsigned short *buf, int nword)
{
	unsigned long sum;
	for(sum = 0; nword > 0; nword--)
	{
		sum += htons(*buf);
		buf++;
	}
	sum = (sum>>16) + (sum&0xffff);
	sum += (sum>>16);
	return ~sum;
}


static void printudpm(unsigned char send_msg[]){
    int i = 0;
    printf("\n=============print udpm===============\n");
    printf("mac:\n");
    for (; i<6; i++)
        printf("%#X ,",send_msg[i]);
    printf("\n");
    for (;i<12;i++)
        printf("%#X ,",send_msg[i]);
    printf("\n");
    for (;i<14;i++)
        printf("%#X ,",send_msg[i]);
    printf("\n");

    printf("ip:\n");
    for (;i<18;i++)
        printf("%#X ,",send_msg[i]);
    printf("\n");
    for (;i<22;i++)
        printf("%#X ,",send_msg[i]);
    printf("\n");
    for (;i<26;i++)
        printf("%#X ,",send_msg[i]);
    printf("\n");
    for (;i<30;i++)
        printf("%u ,",send_msg[i]);
    printf("\n");
    for (;i<34;i++)
        printf("%u ,",send_msg[i]);
    printf("\n");

    printf("udp:\n");
    for (;i<38;i++)
        printf("%#X ,",send_msg[i]);
    printf("\n");
    for (;i<42;i++)
        printf("%#X ,",send_msg[i]);
    printf("\n");

    printf("msg:\n");
    for (;send_msg[i];i++)
        printf("%c",send_msg[i]);

    printf("\n\n");
}

static void 
getudpm(struct rte_mbuf *m, char* mail)
{
	unsigned char send_msg[1024] = {
		//--------------组MAC--------14------
        0xd4, 0xae, 0x52, 0xa3, 0x71, 0xf6,  //dst_mac
        0x78, 0x2b, 0xcb, 0x11, 0x1b, 0xda, //src_mac
		0x08, 0x00,                        //类型：0x0800 IP协议
		//--------------组IP---------20------
		0x45, 0x00, 0x00, 0x00,     //版本号：4, 首部长度：20字节, TOS:0, 16位总长度：
		0x00, 0x00, 0x00, 0x00,    //16位标识、3位标志、13位片偏移都设置0 //比较懵逼
		0x80, 17,  0x00, 0x00,    //TTL：128、协议：UDP（17）、16位首部校验和
        192, 168, 1, 142,
        192, 168, 1, 145,
		//--------------组UDP--------8+78=86------
		0x1f, 0x90, 0x1f, 0x90,            //src_port:0x1f90(8080), dst_port:0x1f90(8080)
		0x00, 0x00, 0x00, 0x00,           //#--16位UDP长度--30个字节、#16位校验和
	};
	unsigned char pseudo_head[1024] = {
		//------------UDP伪头部--------12--
        192, 168, 1, 142,
        192, 168, 1, 145,
		0x00, 17,  0x00, 0x00,             //0,17,#--16位UDP长度--20个字节
	};
	char *data;
	int len = sprintf((char*)&send_msg+42, "%s", mail);

	if(len&1)
		len++;  //如果是奇数，len就应该加1(因为UDP的数据部分如果不为偶数需要用0填补)

	*((unsigned short *)&send_msg[16]) = htons(20+8+len);//IP总长度 = 20 + 8 + len
	*((unsigned short *)&send_msg[14+20+4]) = htons(8+len);//udp总长度 = 8 + len

	//3.UDP伪头部
	*((unsigned short *)&pseudo_head[10]) = htons(8 + len);//伪头部中的udp长度（和真实udp长度是同一个值）

	//4.构建udp校验和需要的数据报 = udp伪头部 + udp数据报
	memcpy(pseudo_head+12, send_msg+34, 8+len);//--计算udp校验和时需要加上伪头部--

	//5.对IP首部进行校验
	*((unsigned short *)&send_msg[24]) = htons(checksum((unsigned short *)(send_msg+14),20/2));

	//6.--对UDP数据进行校验--
	*((unsigned short *)&send_msg[40]) = htons(checksum((unsigned short *)pseudo_head,(12+8+len)/2));

    printudpm(send_msg);

	if(rte_pktmbuf_data_len(m)==0){
	}
	else{
		rte_pktmbuf_trim(m,rte_pktmbuf_data_len(m));
	}

	data = rte_pktmbuf_append(m,len+42);
	if(data==NULL){
		printf("there is no room for mbuf!\n");
		return ;
	}
	memcpy(data,send_msg,42+len);
	return;
}
/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */
static __attribute__((noreturn)) void
lcore_main(struct rte_mempool *mbuf_pool)
{
	uint8_t port = 0;
/*	struct rte_mempool *mbuf_pool;*/
	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	if (rte_eth_dev_socket_id(port) > 0 &&
			rte_eth_dev_socket_id(port) !=
					(int)rte_socket_id())
		printf("WARNING, port %u is on remote NUMA node to "
				"polling thread.\n\tPerformance will "
				"not be optimal.\n", port);

	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
			rte_lcore_id());

/*	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS ,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());*/
	/* Run until the application is quit or killed. */
	for (;;) {
		/*
			send packet
		*/
		struct rte_mbuf *bufs[BURST_SIZE];
		bufs[0] = rte_pktmbuf_alloc(mbuf_pool);
		if(bufs[0]==NULL){
			printf("no more room for mbuf!\n");
		}
		else {
            printf("Your words: ");
            char mail[128];
            gets(mail);
			getudpm(bufs[0],mail);
		}
		const uint16_t nb_tx = rte_eth_tx_burst(port , 0,
				bufs, 1);
		if(nb_tx){
			//printf("send %d packets from port %d\n",nb_tx,port);
            printf("sent\n");
			/* stay */
		}
		/* Free any unsent packets. */
		if (nb_tx) {
			uint16_t buf;
			for (buf = 0; buf < nb_tx; buf++)
				rte_pktmbuf_free(bufs[buf]);
		}
	}
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	unsigned nb_ports;

	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count();
	printf("The number of ports is %d\n",nb_ports);
	if (!nb_ports)
		rte_exit(EXIT_FAILURE, "Error: number of ports must >0\n");

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS +10,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initialize  port 0 for send. */
	if (port_init(0, mbuf_pool) != 0)
		rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8 "\n", 0);

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	/* Call lcore_main on the master core only. */
	lcore_main(mbuf_pool);

	return 0;
}
