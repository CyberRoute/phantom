#define _GNU_SOURCE

#include <Python.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/ethernet.h>
#include <pthread.h>
#include <unistd.h>

// Define missing ARP constants for macOS
#define ARPHRD_ETHER    1       /* Ethernet hardware format */
#define ARPOP_REQUEST   1       /* ARP request */
#define ARPOP_REPLY     2       /* ARP reply */

#ifdef __APPLE__
    struct arphdr {
        unsigned short ar_hrd;   /* Format of hardware address */
        unsigned short ar_pro;   /* Format of protocol address */
        unsigned char  ar_hln;   /* Length of hardware address */
        unsigned char  ar_pln;   /* Length of protocol address */
        unsigned short ar_op;    /* ARP opcode (command) */
    };

    struct ether_arp {
        struct arphdr ea_hdr;    /* Fixed-size header */
        unsigned char arp_sha[6];/* Sender hardware address */
        unsigned char arp_spa[4];/* Sender protocol address */
        unsigned char arp_tha[6];/* Target hardware address */
        unsigned char arp_tpa[4];/* Target protocol address */
    };
#else
    #include <net/if_arp.h>
#endif

// Structure to hold ARP response data
typedef struct {
    char ip_addr[16];
    unsigned char mac_addr[6];
    int found;
} arp_response_t;

// Structure for packet capture thread
typedef struct {
    pcap_t *handle;
    arp_response_t *response;
    struct in_addr target_ip;
    int timeout_ms;
    int finished;
} capture_thread_args_t;

/* 
 * Function to get MAC address for interface
 */
static int get_mac_address(const char *iface, unsigned char *mac) {
    struct ifaddrs *ifap, *ifa;
    int found = 0;

    if (getifaddrs(&ifap) != 0) {
        return -1;
    }

    for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;

        // Check if this is the interface we want and it's a link-layer address
        if ((ifa->ifa_addr->sa_family == AF_LINK) && 
            (strcmp(ifa->ifa_name, iface) == 0)) {
            struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifa->ifa_addr;
            
            if (sdl->sdl_alen == 6) {  // MAC address is 6 bytes
                memcpy(mac, LLADDR(sdl), 6);
                found = 1;
                break;
            }
        }
    }

    freeifaddrs(ifap);
    return found ? 0 : -1;
}

// Function to convert MAC address to string
static void mac_to_string(unsigned char *mac, char *str) {
    snprintf(str, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// Packet capture callback function
static void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    capture_thread_args_t *args = (capture_thread_args_t *)user_data;
    
    struct ether_header *eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_ARP)
        return;

    struct ether_arp *arp_packet = (struct ether_arp *)(packet + sizeof(struct ether_header));
    if (ntohs(arp_packet->ea_hdr.ar_op) != ARPOP_REPLY)
        return;

    // Check if this is the response we're looking for
    if (memcmp(arp_packet->arp_spa, &args->target_ip.s_addr, 4) == 0) {
        memcpy(args->response->mac_addr, arp_packet->arp_sha, 6);
        inet_ntop(AF_INET, arp_packet->arp_spa, args->response->ip_addr, 16);
        args->response->found = 1;
        args->finished = 1;
        pcap_breakloop(args->handle);
    }
}

// Packet capture thread function
static void *capture_thread(void *arg) {
    capture_thread_args_t *args = (capture_thread_args_t *)arg;
    pcap_loop(args->handle, -1, packet_handler, (u_char *)args);
    return NULL;
}

static PyObject *perform_arp_scan(PyObject *self, PyObject *args) {
    char *iface, *src_ip_str, *dst_ip_str;
    int timeout_ms = 1000; // Default timeout 1 second

    if (!PyArg_ParseTuple(args, "sss|i", &iface, &src_ip_str, &dst_ip_str, &timeout_ms)) {
        return NULL;
    }

    // Get interface MAC address
    unsigned char src_mac[6];
    if (get_mac_address(iface, src_mac) < 0) {
        PyErr_SetString(PyExc_RuntimeError, "Failed to get MAC address");
        return NULL;
    }

    // Convert IP addresses
    struct in_addr src_ip, dst_ip;
    if (inet_aton(src_ip_str, &src_ip) == 0 || inet_aton(dst_ip_str, &dst_ip) == 0) {
        PyErr_SetString(PyExc_ValueError, "Invalid IP address");
        return NULL;
    }

    // Open pcap handle
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(iface, 65536, 1, timeout_ms, errbuf);
    if (!handle) {
        PyErr_SetString(PyExc_RuntimeError, errbuf);
        return NULL;
    }

    // Set up packet capture filter for ARP
    struct bpf_program fp;
    char filter_exp[64];
    snprintf(filter_exp, sizeof(filter_exp), "arp src host %s", dst_ip_str);
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        pcap_close(handle);
        PyErr_SetString(PyExc_RuntimeError, "Failed to compile filter");
        return NULL;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        pcap_freecode(&fp);
        pcap_close(handle);
        PyErr_SetString(PyExc_RuntimeError, "Failed to set filter");
        return NULL;
    }
    pcap_freecode(&fp);

    // Prepare ARP request packet
    unsigned char packet[42];
    memset(packet, 0, sizeof(packet));
    
    // Fill Ethernet header
    struct ether_header *eth_hdr = (struct ether_header *)packet;
    memset(eth_hdr->ether_dhost, 0xff, 6);
    memcpy(eth_hdr->ether_shost, src_mac, 6);
    eth_hdr->ether_type = htons(ETHERTYPE_ARP);

    // Fill ARP header
    struct ether_arp *arp_hdr = (struct ether_arp *)(packet + sizeof(struct ether_header));
    arp_hdr->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp_hdr->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
    arp_hdr->ea_hdr.ar_hln = 6;
    arp_hdr->ea_hdr.ar_pln = 4;
    arp_hdr->ea_hdr.ar_op = htons(ARPOP_REQUEST);
    memcpy(arp_hdr->arp_sha, src_mac, 6);
    memcpy(arp_hdr->arp_spa, &src_ip.s_addr, 4);
    memset(arp_hdr->arp_tha, 0, 6);
    memcpy(arp_hdr->arp_tpa, &dst_ip.s_addr, 4);

    // Set up response structure and capture thread
    arp_response_t response = {0};
    capture_thread_args_t thread_args = {
        .handle = handle,
        .response = &response,
        .target_ip = dst_ip,
        .timeout_ms = timeout_ms,
        .finished = 0
    };

    // Start capture thread
    pthread_t tid;
    if (pthread_create(&tid, NULL, capture_thread, &thread_args) != 0) {
        pcap_close(handle);
        PyErr_SetString(PyExc_RuntimeError, "Failed to create capture thread");
        return NULL;
    }

    // Send ARP request
    if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0) {
        pthread_cancel(tid);
        pcap_close(handle);
        PyErr_SetString(PyExc_RuntimeError, "Failed to send ARP packet");
        return NULL;
    }

    // Wait for response or timeout
    while (!thread_args.finished && timeout_ms > 0) {
        usleep(10000); // Sleep for 10ms
        timeout_ms -= 10;
    }

    // Clean up
    pthread_cancel(tid);
    pthread_join(tid, NULL);
    pcap_close(handle);

    // Return results
    if (response.found) {
        char mac_str[18];
        mac_to_string(response.mac_addr, mac_str);
        return Py_BuildValue("{s:s,s:s}", "ip", response.ip_addr, "mac", mac_str);
    }

    Py_RETURN_NONE;
}

// Module method definitions
static PyMethodDef ArpScannerMethods[] = {
    {"perform_arp_scan", perform_arp_scan, METH_VARARGS,
     "Perform an ARP scan with response handling. Args: interface, src_ip, target_ip, [timeout_ms]"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef arpscannermodule = {
    PyModuleDef_HEAD_INIT,
    "arpscanner",
    NULL,
    -1,
    ArpScannerMethods
};

PyMODINIT_FUNC PyInit_arpscanner(void) {
    return PyModule_Create(&arpscannermodule);
}