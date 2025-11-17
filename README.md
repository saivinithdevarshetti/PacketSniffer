#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>

/* Callback function invoked for every captured packet */
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    printf("\n=== Packet Captured ===\n");
    printf("Packet Length: %d bytes\n", header->len);
    printf("Capture Time : %s", ctime((const time_t*)&header->ts.tv_sec));

    printf("First 20 bytes of packet:\n");
    for (int i = 0; i < 20 && i < header->len; i++) {
        printf("%02x ", packet[i]);
    }
    printf("\n========================\n");
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev;

    /* Find a valid network device */
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        printf("Error finding device: %s\n", errbuf);
        return 1;
    }

    printf("Using device: %s\n", dev);

    /* Open the device for sniffing */
    pcap_t *handle = pcap_open_live(dev, 65536, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("Could not open device %s: %s\n", dev, errbuf);
        return 1;
    }

    printf("Starting packet capture... Press Ctrl+C to stop.\n");

    /* Capture packets in an infinite loop */
    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}
