#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "protocols.h"
#include "queue.h"
#include "lib.h"

struct route_table_entry *routeTable;
int routeTableSize;

struct arp_table_entry *arpCache;
int arpCacheSize;

queue packetQueue;

struct queuedPacket {
    char buffer[MAX_PACKET_LEN];
    size_t len;
    uint32_t nextIp;
    int interface;
};

struct trieNode {
    struct trieNode *child[2];
    struct route_table_entry (*route);
} (*trieRoot) = NULL;

void trieInsert(struct route_table_entry *route) {
    uint32_t prefix = ntohl(route->prefix);
    uint32_t mask = ntohl(route->mask);
    size_t maskLen = __builtin_popcount(mask);

    struct trieNode *node = trieRoot;
    for (size_t i = 0; i < maskLen; i++) {
        int bit = (prefix >> (31 - i)) & 1;
        if (node->child[bit] == NULL) {
            node->child[bit] = calloc(1, sizeof(struct trieNode));
            node->child[bit]->child[0] = NULL;
            node->child[bit]->child[1] = NULL;
            node->child[bit]->route = NULL;
        }
        node = node->child[bit];
    }
    node->route = route;
}

struct route_table_entry *lpm_lookup(uint32_t ip) {
    uint32_t orderIp = ntohl(ip);
    struct trieNode *node = trieRoot;
    struct route_table_entry *best = trieRoot->route;

    for (size_t i = 0; i < 32; i++) {
        int bit = (orderIp >> (31 - i)) & 1;
        if (node->child[bit] == NULL) {
            break;
        }
        node = node->child[bit];
        if (node->route != NULL) {
            best = node->route;
        }
    }
    return best;
}

struct arp_table_entry *getArpEntry(uint32_t ip) {
    for (size_t i = 0; i < arpCacheSize; i++) {
        if (arpCache[i].ip == ip) {
            return &arpCache[i];
        }
    }
    return NULL;
}

void sendIcmpError(char *buffer, int type, int code) {
    // [Ether header][IP header][ICMP header][IP header + primii 64 bytes din payload]
    struct ether_header *ethHeader = (struct ether_header *)buffer;
    struct iphdr *ipHeader = (struct iphdr *)(buffer + sizeof(struct ether_header));
    struct icmphdr *icmpHeader = (struct icmphdr *)(buffer + sizeof(struct iphdr) + sizeof(struct ether_header));
    size_t icmpDataLen = sizeof(struct iphdr) + 64;
    size_t totalLen = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + icmpDataLen;

    // Swap MAC addresses
    char reply[MAX_PACKET_LEN];
    memset(reply, 0, MAX_PACKET_LEN);

}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argv + 2, argc - 2);

    struct route_table_entry *routeTable = malloc(sizeof(struct route_table_entry) * 100000);
    int routeTableSize = read_rtable(argv[1], routeTable);
    struct trieNode root = { .child = { NULL, NULL }, .route = NULL };
    trieRoot = &root;
    for (size_t i = 0; i < routeTableSize; i++) {
        trieInsert(&routeTable[i]);
    }

	while (1) {

		size_t interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

    // TODO: Implement the router forwarding logic

    /* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */


	}
}
