# PLAN - Tema 1: Dataplane Router

## Context
Tema 1 PCOM - implementarea dataplane-ului unui router in C. Routerul primeste pachete pe mai multe interfete si trebuie sa le dirijeze conform tabelei de rutare statice. Trebuie implementat in fisierul `router.c` (singurul fisier modificabil). **Nu se modifica** `lib.c` sau fisierele din `include/`.

**Punctaj (din checker):**
| Categorie | Puncte | Nr. teste | Puncte/test |
|-----------|--------|-----------|-------------|
| forward   | 33     | 11        | 3           |
| arp       | 30     | 2         | 15          |
| icmp      | 21     | 3         | 7           |
| lpm       | 16     | 2         | 8           |
| **Total** | **100**|           |             |

---

## Fisiere critice

- `router.c` — singura sursa de implementat
- `include/protocols.h` — structurile: `ether_hdr`, `ip_hdr`, `arp_hdr`, `icmp_hdr`
- `include/lib.h` — API: `checksum()`, `get_interface_ip()`, `get_interface_mac()`, `read_rtable()`, `parse_arp_table()`
- `include/queue.h` — `create_queue()`, `queue_enq()`, `queue_deq()`, `queue_empty()`
- `lib/lib.c` — referinta pentru: `checksum()` face `ntohs()` intern, returneaza host-order; `read_rtable()` stocheaza in network byte order

---

## Pas 0: Include-uri si declaratii globale

Adauga in `router.c`:
```c
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
```

Declara global:
```c
struct route_table_entry *rtable;
int rtable_len;

struct arp_table_entry *arp_cache;
int arp_cache_len;

queue packet_queue;
```

Defineste structura pentru pachetele din coada ARP:
```c
struct queued_packet {
    char buf[MAX_PACKET_LEN];
    size_t len;
    uint32_t next_hop_ip;
    int out_interface;
};
```

---

## Pas 1: Longest Prefix Match eficient (16p) — TRIE

**IMPORTANT**: Binary search pe tabela sortata NU functioneaza corect cand mastile au lungimi diferite (dest_ip & mask variaza per intrare, sparge proprietatea de monotonie a binary search). Foloseste un **trie binar** — e corect in toate cazurile si O(32) per lookup.

### 1a. Structura trie
```c
struct trie_node {
    struct trie_node *children[2];    // bit 0 si bit 1
    struct route_table_entry *route;  // non-NULL daca e un prefix valid
};
```

### 1b. `trie_insert(struct route_table_entry *entry)`
- Converteste prefix si mask la host order cu `ntohl()`
- Calculeaza lungimea mastii: `__builtin_popcount(mask)`
- Parcurge bitii prefix-ului de la MSB (bit 31) la LSB, cate `mask_len` biti
- La fiecare bit, creeaza nod daca nu exista, avanseaza
- La sfarsit, seteaza `node->route = entry`

### 1c. `lpm_lookup(uint32_t dest_ip)`
- Converteste dest_ip la host order cu `ntohl()`
- Parcurge trie-ul de la root, urmand bitii dest_ip (bit 31 → bit 0)
- La fiecare nod, daca `node->route != NULL`, salveaza ca `best`
- Daca copilul nu exista, opreste-te
- Returneaza `best` (cel mai lung prefix gasit)

### 1d. Initializare
```c
trie_root = trie_alloc();
for (int i = 0; i < rtable_len; i++)
    trie_insert(&rtable[i]);
```

---

## Pas 2: Functia `get_arp_entry(uint32_t ip)`

Cautare liniara in cache-ul ARP dinamic. Returneaza pointer la intrare sau NULL.

---

## Pas 3: Functii ICMP (21p)

### 3a. `send_icmp_error(buf, interface, type, code)` — pentru Type 3 (Dest Unreachable) si Type 11 (Time Exceeded)

Structura pachetului trimis:
```
[Ether header][IP header][ICMP header][IP header original + primii 64 biti payload original]
```

Pasi:
1. Parseaza headerele originale din `buf`
2. Creeaza buffer nou `reply[MAX_PACKET_LEN]` (memset 0)
3. **Ethernet**: src = MAC interfata incoming, dst = MAC sursa pachetului original, type = `htons(0x0800)`
4. **IP**: ver=4, ihl=5, tos=0, id=`htons(1)`, frag=0, ttl=64, proto=1(ICMP), src = IP interfata incoming (`inet_addr(get_interface_ip(interface))`), dst = IP sursa pachetului original, tot_len = `htons(sizeof(ip_hdr) + sizeof(icmp_hdr) + sizeof(ip_hdr) + 8)`
5. **ICMP**: mtype = type, mcode = code, un_t zeroed
6. **Payload**: copiaza IP header original + 8 bytes payload
7. Calculeaza checksum ICMP (seteaza check=0, apoi `icmp->check = htons(checksum(...))`)
8. Calculeaza checksum IP (seteaza checksum=0, apoi `ip->checksum = htons(checksum(...))`)
9. `send_to_link(total_len, reply, interface)`

### 3b. `send_icmp_echo_reply(buf, len, interface)` — pentru Type 0 (Echo Reply)

Cel mai simplu: modifica pachetul original in-place:
1. Swap Ethernet src/dst
2. IP: dst = sursa originala, src = IP interfata routerului
3. ICMP: mtype = 0, mcode = 0
4. Pastreaza `id` si `seq` din echo request
5. Recalculeaza checksum ICMP (peste tot payload-ul ICMP, nu doar 8 bytes)
6. Recalculeaza checksum IP
7. Trimite inapoi pe aceeasi interfata

**Checkerul asteapta**: type=0/code=0 (echo reply), type=11/code=0 (time exceeded), type=3/code=0 (dest unreachable).

---

## Pas 4: Functii ARP (30p)

### 4a. `send_arp_request(uint32_t next_hop_ip, int out_interface)`

1. **Ethernet**: dst = `ff:ff:ff:ff:ff:ff` (broadcast), src = MAC `out_interface`, type = `htons(0x0806)`
2. **ARP**: hw_type = `htons(1)`, proto_type = `htons(0x0800)`, hw_len = 6, proto_len = 4, opcode = `htons(1)`, shwa = MAC `out_interface`, sprotoa = IP `out_interface`, thwa = `00:00:00:00:00:00`, tprotoa = `next_hop_ip`
3. `send_to_link(sizeof(ether_hdr) + sizeof(arp_hdr), buf, out_interface)`

**ATENTIE**: ARP request se trimite pe interfata din tabela de rutare (`best_route->interface`), NU pe interfata pe care a venit pachetul!

### 4b. `send_arp_reply(buf, interface)`

Raspunde la ARP request destinat routerului:
1. Parseaza ARP request din `buf`
2. Construieste ARP reply: opcode = `htons(2)`, swap sender/target, completeaza cu MAC/IP interfata routerului
3. Trimite pe aceeasi interfata

---

## Pas 5: Initializare in `main()` (inainte de while loop)

```c
setvbuf(stdout, NULL, _IONBF, 0);  // debug unbuffered

rtable = malloc(sizeof(struct route_table_entry) * 100000);
rtable_len = read_rtable(argv[1], rtable);

// Build trie
trie_root = trie_alloc();
for (int i = 0; i < rtable_len; i++)
    trie_insert(&rtable[i]);

arp_cache = malloc(sizeof(struct arp_table_entry) * 100);
arp_cache_len = 0;

packet_queue = create_queue();
```

---

## Pas 6: Logica principala in `while(1)` loop

### 6a. Parseaza Ethernet header
```c
struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;
```

### 6b. Verifica MAC destinatie
Accepta doar: MAC interfata curenta SAU broadcast `ff:ff:ff:ff:ff:ff`. Altfel `continue`.

### 6c. Branch pe EtherType

**Daca `ntohs(eth_hdr->ethr_type) == 0x0806` (ARP)**:
1. Parseaza `struct arp_hdr *arp = (buf + sizeof(ether_hdr))`
2. **ARP Request** (opcode == 1): verifica daca `tprotoa == IP-ul interfetei curente` → `send_arp_reply()`
3. **ARP Reply** (opcode == 2):
   - Adauga in `arp_cache`: ip = `arp->sprotoa`, mac = `arp->shwa`
   - Parcurge `packet_queue`: pentru fiecare pachet, cauta MAC in cache
     - Gasit → rescrie L2 header, `send_to_link()`, `free()`
     - Negasit → re-enqueue (foloseste o coada temporara)

**Daca `ntohs(eth_hdr->ethr_type) == 0x0800` (IPv4)**:
1. Parseaza `struct ip_hdr *ip = (buf + sizeof(ether_hdr))`
2. **Verifica daca pachetul e pentru router** (compara `ip->dest_addr` cu IP-urile tuturor interfetelor)
   - Da + ICMP Echo Request (proto==1, mtype==8) → `send_icmp_echo_reply()`
   - Da + altceva → `continue` (drop)
3. **Verifica checksum IP**: salveaza `recv_checksum`, seteaza pe 0, calculeaza, compara. Daca difera → `continue`
4. **Verifica TTL**: daca `ttl <= 1` → restaureaza checksum original, `send_icmp_error(buf, interface, 11, 0)` + `continue`
5. **Decrementeaza TTL**: `ip->ttl--`
6. **Recalculeaza checksum IP**: seteaza pe 0, calculeaza, stocheaza cu `htons()`
7. **LPM lookup**: `lpm_lookup(ip->dest_addr)`. Daca NULL → restaureaza TTL si checksum, `send_icmp_error(buf, interface, 3, 0)` + `continue`
8. **Cauta MAC next_hop in ARP cache**: `get_arp_entry(best_route->next_hop)`
   - Negasit → `malloc` queued_packet, copiaza buf+len+next_hop+interface, `queue_enq()`, `send_arp_request(best_route->next_hop, best_route->interface)`, `continue`
9. **Rescrie L2 header**: dst = MAC next_hop (din ARP cache), src = MAC interfata de iesire (`get_interface_mac(best_route->interface, ...)`)
10. **Trimite**: `send_to_link(len, buf, best_route->interface)`

**Altfel** → `continue` (drop pachete cu EtherType necunoscut)

---

## Ordinea implementarii (recomandata)

1. **Trie (alloc + insert)** — fara dependinte
2. **`lpm_lookup()`** — depinde de trie
3. **`get_arp_entry()`** — trivial
4. **ICMP functions** — depinde de structurile header
5. **ARP functions** — depinde de structurile header
6. **Initializare in main** — depinde de 1-5
7. **Branch ARP in loop** — depinde de 4, 5
8. **Branch IPv4 in loop** — depinde de tot

---

## Capcane critice

1. **`checksum()` returneaza host-order** → stocheaza cu `htons()`: `ip->checksum = htons(checksum(...))`
2. **`get_interface_ip()` returneaza string** → converteste cu `inet_addr()` pentru uint32_t in network order
3. **ARP request pe interfata corecta** → `best_route->interface`, NU interfata de intrare
4. **Queue stocheaza pointeri** → TREBUIE `malloc` copie, altfel `buf` se suprascrie la urmatorul `recv_from_any_link`
5. **Endianness**: toate campurile multi-byte din headere sunt network order. Citire: `ntohs()`/`ntohl()`. Scriere: `htons()`/`htonl()`
6. **Binary search NU merge pentru LPM** — mastile diferite sparg monotonia, foloseste trie
7. **ICMP error payload**: include IP header original + primii 8 bytes din payload-ul de deasupra IP
8. **`sizeof(struct ether_hdr)` = 14**, `sizeof(struct ip_hdr)` = 20, `sizeof(struct arp_hdr)` = 28, `sizeof(struct icmp_hdr)` = 8
9. **Checksum ICMP pentru echo reply**: se calculeaza peste ICMP header + tot data-ul de deasupra (nu doar headerul de 8 bytes)
10. **Nu include `arp_table.txt` in arhiva** daca implementezi ARP dinamic (altfel dezactiveaza testele ARP)

---

## Verificare / Testare

1. **Compilare**: `make clean && make`
2. **Testare manuala**:
   - Porneste topologia: `sudo python3 checker/topo.py`
   - Pe terminalele routerelor: `make run_router0` / `make run_router1`
   - De pe hosturi: `ping`, `arping`, `ping -t 1`, `traceroute`
   - Wireshark pe interfetele relevante
3. **Checker automat**: `./checker/checker.sh`
   - Rezultate in `host_outputs/` (stdout, stderr, pcap per test)
   - Test individual: `sudo python3 checker/topo.py run router_arp_reply`
4. **Lista teste**:
   - `router_arp_reply` — ARP request de la host, asteapta reply
   - `router_arp_request` — pachet IP catre host, routerul trimite ARP request
   - `forward` / `forward_no_arp` / `forwardXY` — forwarding corect intre hosturi
   - `ttl` — verifica TTL=63 dupa decrement (original=64)
   - `checksum` — checksum recalculat corect
   - `wrong_checksum` — pachet cu checksum gresit = drop (0 pachete la dest)
   - `router_icmp` — echo request catre router, asteapta echo reply
   - `icmp_timeout` — TTL=1, asteapta ICMP type=11/code=0
   - `host_unreachable` — dest=10.0.0.1 (nu exista in rtable), asteapta ICMP type=3/code=0
   - `forward10packets` / `forward10across` — 10 pachete (teste LPM eficienta)

---

## Trimitere

- `./create_archive.sh` pentru generarea arhivei
- Upload pe Moodle
- **NU include**: `arp_table.txt` (daca ai ARP dinamic), fisiere modificate din `lib/` sau `include/`
- Mediu testare: Ubuntu 20.04, GCC 9.4.0
