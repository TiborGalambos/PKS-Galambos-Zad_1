#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>

#pragma warning(disable : 4996)

int menu()
{
    int n = 1, filenum;
    //system("cls");
    printf("Vyberte subor na analyzovanie\n\n");
    for (int i = 1; i <= 9; i++)
        printf("%d. eth-%d.pcap\n", n++, i);

    for (int i = 0; i <= 29; i++)
        printf("%d. trace-%d.pcap\n", n++, i);

    printf("\n0 - Koniec\nCISLO: ");
    scanf("%d", &filenum);

    //system("cls");
    
    return filenum;
}

void main()
{
    char errbuff[PCAP_ERRBUF_SIZE];
    char fname[40];
    
    struct pcap_pkthdr* head;
    const u_char *packet;

    int num = 1, i = 0, len = 0, filenum;
    char option = 'b';
    char buf[2];
    pcap_t* file;

    while (filenum = menu() != 0)
    {
        if (filenum >=1 && filenum <= 38) // zmenit
        {   
            memset(fname, '\0', sizeof(fname));

            if (filenum >= 1 && filenum <= 9)
            {
                strcpy(fname, "vzorky_pcap_na_analyzu/eth-");
                itoa(filenum, buf, 10);
                strcat(fname, buf);
            }
                
            else if (filenum >= 10)
            {
                strcpy(fname, "vzorky_pcap_na_analyzu/trace-");
                itoa(filenum - 10, buf, 10);
                strcat(fname, buf);
            }
                
            strcat(fname, ".pcap");
        }
        else return;

        file = pcap_open_offline(fname, errbuff);

        printf("SUBOR: %s\n", fname);

        while (pcap_next_ex(file, &head, &packet) >= 0)
        {
            printf("RAMEC #%d\n\n", num++);
            printf("Dlzka ramca pcap API: %d\n", head->caplen);

            len = head->caplen;
            if (len + 4 <= 64) len = 64;
            else len += 4;

            printf("Dlzka ramca prenasaneho po mediu: %d\n", len);

            printf("\nZdrojova MAC: \t");

            for (i = 6; i < 12; i++)
                printf("%.2x ", packet[i]);

            printf("\nCielova MAC: \t");

            for (i = 0; i < 6; i++)
                printf("%.2x ", packet[i]);

            printf("\n");

            if ((packet[12] * 256) + packet[13] > 0x600)
                printf("\nEthernet II\n");
            else
                if ((packet[14] * 256) + packet[15] == 0xffff)
                    printf("\nIEEE 802.3 RAW\n");
                else
                    if ((packet[14] * 256) + packet[15] == 0xaaaa)
                        printf("\nIEEE 802.3 LLC + SNAP\n");
                    else
                        printf("\nIEEE 802.3 LLC\n");

            for (i = 0; i < (int)head->caplen; i++)
            {
                if ((i % 8) == 0) printf(" ");
                if ((i % 16) == 0) printf("\n");
                printf("%.2x ", packet[i]);
            }
            
            printf("\n\n------------------------------------------------\n\n");

        }
    }
    

    return;
}