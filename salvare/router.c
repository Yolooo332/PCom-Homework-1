#include "protocols.h"
#include "queue.h"
#include "lib.h"

#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/* Global state */
struct route_table_entry *rtable;
int rtable_len;

struct arp_table_entry *arp_cache;
int arp_cache_len;

queue packet_queue;

/* Packet waiting for ARP resolution */
struct queued_packet {
	char buf[MAX_PACKET_LEN];
	size_t len;
	uint32_t next_hop_ip;
	int out_interface;
};

/* ===================== Pas 1: LPM cu trie ===================== */

struct trie_node {
	struct trie_node *children[2];
	struct route_table_entry *route;
};

struct trie_node *trie_root;

struct trie_node *trie_alloc(void)
{
	struct trie_node *node = calloc(1, sizeof(struct trie_node));
	DIE(node == NULL, "calloc trie_node");
	return node;
}

void trie_insert(struct route_table_entry *entry)
{
	struct trie_node *node = trie_root;
	uint32_t prefix = ntohl(entry->prefix);
	uint32_t mask = ntohl(entry->mask);
	int mask_len = __builtin_popcount(mask);

	for (int i = 31; i >= 32 - mask_len; i--) {
		int bit = (prefix >> i) & 1;
		if (node->children[bit] == NULL)
			node->children[bit] = trie_alloc();
		node = node->children[bit];
	}
	node->route = entry;
}

struct route_table_entry *lpm_lookup(uint32_t dest_ip)
{
	struct trie_node *node = trie_root;
	struct route_table_entry *best = NULL;
	uint32_t ip = ntohl(dest_ip);

	for (int i = 31; i >= 0; i--) {
		if (node == NULL)
			break;
		if (node->route != NULL)
			best = node->route;
		int bit = (ip >> i) & 1;
		node = node->children[bit];
	}
	if (node != NULL && node->route != NULL)
		best = node->route;

	return best;
}

/* ===================== Pas 2: ARP cache lookup ===================== */

struct arp_table_entry *get_arp_entry(uint32_t ip)
{
	for (int i = 0; i < arp_cache_len; i++) {
		if (arp_cache[i].ip == ip)
			return &arp_cache[i];
	}
	return NULL;
}

/* ===================== Pas 3: ICMP ===================== */

void send_icmp_error(char *orig_buf, size_t interface, uint8_t type, uint8_t code)
{
	char reply[MAX_PACKET_LEN];
	memset(reply, 0, MAX_PACKET_LEN);

	struct ether_hdr *orig_eth = (struct ether_hdr *)orig_buf;
	struct ip_hdr *orig_ip = (struct ip_hdr *)(orig_buf + sizeof(struct ether_hdr));

	/* Ethernet header */
	struct ether_hdr *eth = (struct ether_hdr *)reply;
	memcpy(eth->ethr_dhost, orig_eth->ethr_shost, 6);
	get_interface_mac(interface, eth->ethr_shost);
	eth->ethr_type = htons(0x0800);

	/* IP header */
	struct ip_hdr *ip = (struct ip_hdr *)(reply + sizeof(struct ether_hdr));
	ip->ver = 4;
	ip->ihl = 5;
	ip->tos = 0;
	ip->id = htons(1);
	ip->frag = 0;
	ip->ttl = 64;
	ip->proto = 1; /* ICMP */
	ip->source_addr = inet_addr(get_interface_ip(interface));
	ip->dest_addr = orig_ip->source_addr;
	ip->tot_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr)
	              + sizeof(struct ip_hdr) + 8);

	/* ICMP header */
	struct icmp_hdr *icmp = (struct icmp_hdr *)(reply + sizeof(struct ether_hdr)
	                        + sizeof(struct ip_hdr));
	icmp->mtype = type;
	icmp->mcode = code;

	/* Payload: original IP header + first 64 bits (8 bytes) of original payload */
	char *payload = reply + sizeof(struct ether_hdr) + sizeof(struct ip_hdr)
	                + sizeof(struct icmp_hdr);
	memcpy(payload, orig_ip, sizeof(struct ip_hdr) + 8);

	/* ICMP checksum */
	icmp->check = 0;
	icmp->check = htons(checksum((uint16_t *)icmp,
	              sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8));

	/* IP checksum */
	ip->checksum = 0;
	ip->checksum = htons(checksum((uint16_t *)ip, sizeof(struct ip_hdr)));

	size_t total_len = sizeof(struct ether_hdr) + ntohs(ip->tot_len);
	send_to_link(total_len, reply, interface);
}

void send_icmp_echo_reply(char *buf, size_t len, size_t interface)
{
	struct ether_hdr *eth = (struct ether_hdr *)buf;
	struct ip_hdr *ip = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
	struct icmp_hdr *icmp = (struct icmp_hdr *)(buf + sizeof(struct ether_hdr)
	                        + sizeof(struct ip_hdr));

	/* Swap Ethernet src/dst */
	uint8_t tmp_mac[6];
	memcpy(tmp_mac, eth->ethr_dhost, 6);
	memcpy(eth->ethr_dhost, eth->ethr_shost, 6);
	memcpy(eth->ethr_shost, tmp_mac, 6);

	/* Swap IP src/dst */
	uint32_t tmp_ip = ip->source_addr;
	ip->source_addr = ip->dest_addr;
	ip->dest_addr = tmp_ip;

	/* ICMP: type=0 (echo reply), code=0 */
	icmp->mtype = 0;
	icmp->mcode = 0;

	/* Recalculate ICMP checksum (over entire ICMP portion) */
	icmp->check = 0;
	size_t icmp_len = ntohs(ip->tot_len) - sizeof(struct ip_hdr);
	icmp->check = htons(checksum((uint16_t *)icmp, icmp_len));

	/* Recalculate IP checksum */
	ip->checksum = 0;
	ip->checksum = htons(checksum((uint16_t *)ip, sizeof(struct ip_hdr)));

	send_to_link(len, buf, interface);
}

/* ===================== Pas 4: ARP ===================== */

void send_arp_request(uint32_t next_hop_ip, int out_interface)
{
	char arp_buf[MAX_PACKET_LEN];
	memset(arp_buf, 0, MAX_PACKET_LEN);

	/* Ethernet header */
	struct ether_hdr *eth = (struct ether_hdr *)arp_buf;
	memset(eth->ethr_dhost, 0xff, 6); /* broadcast */
	get_interface_mac(out_interface, eth->ethr_shost);
	eth->ethr_type = htons(0x0806);

	/* ARP header */
	struct arp_hdr *arp = (struct arp_hdr *)(arp_buf + sizeof(struct ether_hdr));
	arp->hw_type = htons(1);         /* Ethernet */
	arp->proto_type = htons(0x0800); /* IPv4 */
	arp->hw_len = 6;
	arp->proto_len = 4;
	arp->opcode = htons(1);          /* ARP Request */
	get_interface_mac(out_interface, arp->shwa);
	arp->sprotoa = inet_addr(get_interface_ip(out_interface));
	memset(arp->thwa, 0, 6);
	arp->tprotoa = next_hop_ip;

	size_t total_len = sizeof(struct ether_hdr) + sizeof(struct arp_hdr);
	send_to_link(total_len, arp_buf, out_interface);
}

void send_arp_reply(char *orig_buf, size_t interface)
{
	char reply[MAX_PACKET_LEN];
	memset(reply, 0, MAX_PACKET_LEN);

	struct ether_hdr *orig_eth = (struct ether_hdr *)orig_buf;
	struct arp_hdr *orig_arp = (struct arp_hdr *)(orig_buf + sizeof(struct ether_hdr));

	/* Ethernet header */
	struct ether_hdr *eth = (struct ether_hdr *)reply;
	memcpy(eth->ethr_dhost, orig_eth->ethr_shost, 6);
	get_interface_mac(interface, eth->ethr_shost);
	eth->ethr_type = htons(0x0806);

	/* ARP header */
	struct arp_hdr *arp = (struct arp_hdr *)(reply + sizeof(struct ether_hdr));
	arp->hw_type = htons(1);
	arp->proto_type = htons(0x0800);
	arp->hw_len = 6;
	arp->proto_len = 4;
	arp->opcode = htons(2);          /* ARP Reply */
	get_interface_mac(interface, arp->shwa);
	arp->sprotoa = inet_addr(get_interface_ip(interface));
	memcpy(arp->thwa, orig_arp->shwa, 6);
	arp->tprotoa = orig_arp->sprotoa;

	size_t total_len = sizeof(struct ether_hdr) + sizeof(struct arp_hdr);
	send_to_link(total_len, reply, interface);
}

/* ===================== Main ===================== */

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argv + 2, argc - 2);

	setvbuf(stdout, NULL, _IONBF, 0);

	/* Pas 5: Initializare */
	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	DIE(rtable == NULL, "malloc rtable");
	rtable_len = read_rtable(argv[1], rtable);

	/* Build trie for LPM */
	trie_root = trie_alloc();
	for (int i = 0; i < rtable_len; i++)
		trie_insert(&rtable[i]);

	arp_cache = malloc(sizeof(struct arp_table_entry) * 100);
	DIE(arp_cache == NULL, "malloc arp_cache");
	arp_cache_len = 0;

	packet_queue = create_queue();

	while (1) {
		size_t interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		/* Pas 6a: Parse Ethernet header */
		struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;

		/* Pas 6b: Verify destination MAC */
		uint8_t my_mac[6];
		get_interface_mac(interface, my_mac);
		uint8_t broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

		if (memcmp(eth_hdr->ethr_dhost, my_mac, 6) != 0 &&
		    memcmp(eth_hdr->ethr_dhost, broadcast_mac, 6) != 0) {
			continue;
		}

		/* Pas 6c: Branch on EtherType */
		if (ntohs(eth_hdr->ethr_type) == 0x0806) {
			/* ===== ARP ===== */
			struct arp_hdr *arp = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));

			if (ntohs(arp->opcode) == 1) {
				/* ARP Request */
				uint32_t my_ip = inet_addr(get_interface_ip(interface));
				if (arp->tprotoa == my_ip) {
					send_arp_reply(buf, interface);
				}
			} else if (ntohs(arp->opcode) == 2) {
				/* ARP Reply - add to cache */
				arp_cache[arp_cache_len].ip = arp->sprotoa;
				memcpy(arp_cache[arp_cache_len].mac, arp->shwa, 6);
				arp_cache_len++;

				/* Process queued packets */
				queue tmp_queue = create_queue();
				while (!queue_empty(packet_queue)) {
					struct queued_packet *qp = queue_deq(packet_queue);
					struct arp_table_entry *entry = get_arp_entry(qp->next_hop_ip);
					if (entry != NULL) {
						struct ether_hdr *qeth = (struct ether_hdr *)qp->buf;
						memcpy(qeth->ethr_dhost, entry->mac, 6);
						get_interface_mac(qp->out_interface, qeth->ethr_shost);
						qeth->ethr_type = htons(0x0800);
						send_to_link(qp->len, qp->buf, qp->out_interface);
						free(qp);
					} else {
						queue_enq(tmp_queue, qp);
					}
				}
				/* Move remaining packets back */
				while (!queue_empty(tmp_queue)) {
					queue_enq(packet_queue, queue_deq(tmp_queue));
				}
			}

		} else if (ntohs(eth_hdr->ethr_type) == 0x0800) {
			/* ===== IPv4 ===== */
			struct ip_hdr *ip = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));

			/* 1. Check if packet is destined to the router */
			int is_for_router = 0;
			for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
				if (ip->dest_addr == inet_addr(get_interface_ip(i))) {
					is_for_router = 1;
					break;
				}
			}

			if (is_for_router) {
				if (ip->proto == 1) {
					struct icmp_hdr *icmp = (struct icmp_hdr *)(buf
					    + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
					if (icmp->mtype == 8) {
						send_icmp_echo_reply(buf, len, interface);
					}
				}
				continue;
			}

			/* 2. Verify IP checksum */
			uint16_t recv_checksum = ip->checksum;
			ip->checksum = 0;
			uint16_t computed = htons(checksum((uint16_t *)ip, sizeof(struct ip_hdr)));
			if (recv_checksum != computed) {
				continue;
			}

			/* 3. Check TTL */
			if (ip->ttl <= 1) {
				ip->checksum = recv_checksum;
				send_icmp_error(buf, interface, 11, 0);
				continue;
			}

			/* 4. Decrement TTL */
			ip->ttl--;

			/* 5. Recalculate IP checksum */
			ip->checksum = 0;
			ip->checksum = htons(checksum((uint16_t *)ip, sizeof(struct ip_hdr)));

			/* 6. LPM lookup */
			struct route_table_entry *best_route = lpm_lookup(ip->dest_addr);
			if (best_route == NULL) {
				/* Restore original for ICMP payload */
				ip->ttl++;
				ip->checksum = 0;
				ip->checksum = htons(checksum((uint16_t *)ip, sizeof(struct ip_hdr)));
				send_icmp_error(buf, interface, 3, 0);
				continue;
			}

			/* 7. ARP cache lookup for next hop */
			struct arp_table_entry *arp_entry = get_arp_entry(best_route->next_hop);
			if (arp_entry == NULL) {
				/* Queue packet and send ARP request */
				struct queued_packet *qp = malloc(sizeof(struct queued_packet));
				DIE(qp == NULL, "malloc queued_packet");
				memcpy(qp->buf, buf, len);
				qp->len = len;
				qp->next_hop_ip = best_route->next_hop;
				qp->out_interface = best_route->interface;
				queue_enq(packet_queue, qp);

				send_arp_request(best_route->next_hop, best_route->interface);
				continue;
			}

			/* 8. Rewrite L2 header */
			memcpy(eth_hdr->ethr_dhost, arp_entry->mac, 6);
			get_interface_mac(best_route->interface, eth_hdr->ethr_shost);

			/* 9. Forward */
			send_to_link(len, buf, best_route->interface);
		}
		/* else: unknown EtherType, drop */
	}
}
