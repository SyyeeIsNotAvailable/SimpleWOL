#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

#define MAC_LEN 6
#define PACKET_SIZE 102

// Ajoute les ":" automatiquement si besoin
void format_mac_colons(const char* input, char* output) {
    size_t len = strlen(input);
    if (len == 12) { // Format sans séparateur
        int j = 0;
        for (int i = 0; i < 12; i += 2) {
            output[j++] = input[i];
            output[j++] = input[i + 1];
            if (i < 10) output[j++] = ':';
        }
        output[j] = '\0';
    }
    else {
        strcpy(output, input); // Déjà formaté
    }
}

// Convertit une adresse MAC en tableau de 6 octets
int parse_mac(const char* mac_str, unsigned char* mac) {
    int values[MAC_LEN];
    int count =
        sscanf(mac_str, "%x:%x:%x:%x:%x:%x",
            &values[0], &values[1], &values[2],
            &values[3], &values[4], &values[5]);
    if (count != MAC_LEN) {
        count = sscanf(mac_str, "%x-%x-%x-%x-%x-%x",
            &values[0], &values[1], &values[2],
            &values[3], &values[4], &values[5]);
        if (count != MAC_LEN) {
            return -1;
        }
    }
    for (int i = 0; i < MAC_LEN; i++) {
        if (values[i] < 0 || values[i] > 255) {
            return -1;
        }
        mac[i] = (unsigned char)values[i];
    }
    return 0;
}

// Crée le paquet magique WoL
void create_magic_packet(unsigned char* packet, const unsigned char* mac) {
    memset(packet, 0xFF, 6);
    for (int i = 1; i <= 16; i++) {
        memcpy(packet + i * MAC_LEN, mac, MAC_LEN);
    }
}

int main() {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "Erreur : impossible d'initialiser Winsock.\n");
        return 1;
    }

    while (1) {
        char mac_str_raw[32];
        char mac_str[32];
        char ip_str[64];
        int port;

        printf("Adresse MAC (format XX:XX:XX:XX:XX:XX ou XXXXXXXXXXXX) : ");
        scanf("%31s", mac_str_raw);

        format_mac_colons(mac_str_raw, mac_str);

        printf("Adresse IP ou DNS : ");
        scanf("%63s", ip_str);

        printf("Port UDP (par defaut 9) : ");
        if (scanf("%d", &port) != 1) {
            port = 9;
        }
        if (port <= 0 || port > 65535) {
            fprintf(stderr, "Avertissement : port invalide, utilisation du port 9.\n");
            port = 9;
        }

        unsigned char mac[MAC_LEN];
        if (parse_mac(mac_str, mac) != 0) {
            fprintf(stderr, "Erreur : adresse MAC invalide.\n");
            continue; // Retour au début
        }

        unsigned char packet[PACKET_SIZE];
        create_magic_packet(packet, mac);

        SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock == INVALID_SOCKET) {
            fprintf(stderr, "Erreur socket : %d\n", WSAGetLastError());
            continue;
        }

        BOOL broadcast = TRUE;
        if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (char*)&broadcast, sizeof(broadcast)) == SOCKET_ERROR) {
            fprintf(stderr, "Erreur setsockopt : %d\n", WSAGetLastError());
            closesocket(sock);
            continue;
        }

        struct addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP;

        struct addrinfo* res = NULL;
        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%d", port);

        int gai = getaddrinfo(ip_str, port_str, &hints, &res);
        if (gai != 0 || res == NULL) {
            fprintf(stderr, "Erreur : adresse IP/DNS invalide.\n");
            if (res) freeaddrinfo(res);
            closesocket(sock);
            continue;
        }

        int send_res = sendto(sock, (const char*)packet, sizeof(packet), 0, res->ai_addr, (int)res->ai_addrlen);
        if (send_res == SOCKET_ERROR) {
            fprintf(stderr, "Erreur sendto : %d\n", WSAGetLastError());
            freeaddrinfo(res);
            closesocket(sock);
            continue;
        }

        printf("Succes : paquet WoL envoye a %s (%s:%d)\n", mac_str, ip_str, port);

        freeaddrinfo(res);
        closesocket(sock);

        // Demande à l'utilisateur s'il veut recommencer
        char again[8];
        printf("Voulez-vous envoyer un autre paquet ? (o/n) : ");
        scanf("%7s", again);
        if (again[0] != 'o' && again[0] != 'O') {
            break;
        }
    }

    WSACleanup();
    return 0;
}