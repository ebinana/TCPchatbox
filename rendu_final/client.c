#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdbool.h>
#include <ctype.h>
#include <pthread.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "common.h"
#include "msg_struct.h"

#define MAX_NICK_LEN 12  //Taille maximale du pseudo


char USERNAME[NICK_LEN] = {0}; // Pseudo de l'utilisateur
char CURRENT_CHANNEL[INFOS_LEN] = {0}; // Nom du channel actuel

bool file_need_response = false; //  indique si l'on attend une réponse pour un transfert de fichier
char latest_char = {0}; //  contient la dernière touche pressée par l'utilisateur

char FILENAME[INFOS_LEN] = {0}; // contient le nom du fichier à envoyer

/*
 * Fonction qui permet de faire une allocation mémoire "safe"
 */
void *safe_malloc(size_t size) {
    void *ptr = malloc(size);
    if (!ptr) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

/*
 * Fonction qui permet de copier une chaine de caractères dans une autre
 */
void strncpy_safe(char *dest, const char *src, size_t dest_size) {
    if (dest_size == 0) return;

    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';
}

/*
 * Fonction qui permet de savoir si un fichier existe
 */
int does_file_exist(const char *filename) {
    struct stat buffer;
    return (stat(filename, &buffer) == 0);
}


/*
 * Fonction qui permet de créer un dossier si il n'existe pas et retourne 0 si tout s'est bien passé
 */
int ensure_directory_exists(const char *dir) {
    struct stat st;

    // Vérifie si le répertoire existe déjà
    if (stat(dir, &st) == 0) {
        // Vérifie si c'est bien un répertoire
        if (S_ISDIR(st.st_mode)) {
            return 0; // Le répertoire existe déjà
        }
    }

    // Si le répertoire n'existe pas, tente de le créer
    if (mkdir(dir, 0700) == -1) { // 0700 donne des droits de lecture, écriture et exécution seulement au propriétaire
        perror("mkdir");
        return -1;
    }

    return 0;
}

/*
 * Fonction qui permet de recevoir des données
 */
ssize_t receive_data(int sockfd, void *buffer, size_t length) {
    ssize_t total_bytes_received = 0;
    while (total_bytes_received < length) { // Tant qu'on a pas reçu la totalité des données
        ssize_t bytes_received = recv(sockfd, (char *) buffer + total_bytes_received,
                                      length - total_bytes_received, 0); // On reçoit les données restantes

        if (bytes_received <= 0) {
            return bytes_received;
        }

        total_bytes_received += bytes_received;
    }
    return total_bytes_received;
}

/*
 * Fonction qui permet d'envoyer des données
 */
ssize_t send_data(int sockfd,  void *buffer, size_t length) {
    ssize_t total_bytes_sent = 0;
    while (total_bytes_sent < length) { // Tant qu'on a pas envoyé la totalité des données
        ssize_t bytes_sent = send(sockfd, (char *) buffer + total_bytes_sent,
                                  length - total_bytes_sent, 0); // On envoie les données restantes

        if (bytes_sent <= 0) {
            return bytes_sent;
        }

        total_bytes_sent += bytes_sent;
    }
    return total_bytes_sent;
}

/*
 * Fonction qui permet d'obtenir la taille d'un fichier
 */
int getfilesize(const char *filename) {
    struct stat st;

    if (stat(filename, &st) == 0) {
        return st.st_size; // Retourne la taille du fichier en bytes
    } else {
        return -1; // Échec de l'obtention de la taille du fichier
    }
}


/*
 * Fonction qui permet d'envoyer un fichier
 */
int send_file(int socket_fd, const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        perror("fopen");
        return -1;
    }

    char buffer[1024]; // Buffer de 1KB
    size_t bytes_read; // Nombre d'octets lus

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) { // Tant qu'on a pas lu tout le fichier

        send_data(socket_fd, buffer, bytes_read); // On envoie les données lues
    }

    fclose(file);
    return 0;
}

/*
 * Fonction qui permet de recevoir un fichier
 */
int receive_file(int socket_fd, const char *filename , int filesize){
    const char *inbox_dir = "inbox"; // Dossier de réception des fichiers
    if (ensure_directory_exists(inbox_dir) == -1) {  // On s'assure que le dossier existe et on le crée si besoin
        return -1;
    }

    char file_path[INFOS_LEN];
    snprintf(file_path, sizeof(file_path), "%s/%s", inbox_dir, filename); // permet de constuire le chemin du fichier

    FILE *file = fopen(file_path, "wb"); // On ouvre le fichier en écriture binaire
    if (file == NULL) {
        perror("fopen");
        return -1;
    }


    char buffer[1024];
    ssize_t bytes_received;
    ssize_t total_bytes_received = 0;


    while (total_bytes_received < filesize){ // Tant qu'on a pas reçu la totalité du fichier
        bytes_received = recv(socket_fd, buffer, sizeof(buffer), 0); // On reçoit les données
        if(bytes_received == 0 || bytes_received == -1){
            break;
        }
        fwrite(buffer, 1, bytes_received, file); // On écrit les données dans le fichier
        total_bytes_received += bytes_received; // On met à jour le nombre d'octets reçus
    }


    if (bytes_received == -1) {
        perror("recv");
        fclose(file);
        return -1;
    }

    fclose(file);
    return 0;
}


/*
 * Cette fonction permet de savoir si un pseudo est valide
 */
bool isInvalidUsername(const char *str) {

    int length = strlen(str);
    if (length <= 0 || length > MAX_NICK_LEN) { // si le pseudo est vide ou trop long
        return true;
    }
    for (int i = 0; i < length; i++) {  // si le pseudo contient des caractères spéciaux
        if (!isalnum(str[i])) {
            return true;
        }
    }
    return false;
}

/*
 * cette fonction enelve les caracteres de fin de ligne
 */
void remove_newline(char *str) {
    char *newline_position = strchr(str, '\n');
    if (newline_position) {
        *newline_position = '\0';
    }
}

/*
 * Cette fonction transforme un buffer en un tableau de chaines de carateres délimités par des espaces
 */
char **buff_to_argv_like(char *message) {
    int argc = 0;
    char **argv = NULL;
    char *token = strtok(message, " ");

    while (token != NULL) { // Tant qu'il y a des 'mots' dans le buffer
        remove_newline(token); // On enlève le caractère de fin de ligne
        argv = realloc(argv, (argc + 2) * sizeof(char *)); // On alloue de la mémoire pour le nouveau mot
        if (argv == NULL) {
            perror("realloc");
            exit(EXIT_FAILURE);
        }
        argv[argc] = token; // On ajoute le mot au tableau
        argc++; // On met à jour le nombre de mots

        token = strtok(NULL, " "); // On passe au mot suivant
    }
    argv[argc] = NULL; // On ajoute un pointeur NULL à la fin du tableau

    return argv;
}


/*
 * Cette fonction permet de créer la socket de discussion 'serveur' en pear to pear pour le transfert de fichier
 */
int create_filetransfert_socket_listen(char ip[16], char port[6]) {


    int fd = socket(AF_INET, SOCK_STREAM, 0); // Création de la socket
    if (fd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int) {1}, sizeof(int)); // Permet de réutiliser l'adresse

    struct sockaddr_in addr;
    addr.sin_family = AF_INET; // On utilise IPv4
    addr.sin_port = htons(atoi(port)); // On convertit le port
    inet_aton(ip, &addr.sin_addr); // On convertit l'adresse IP

    int ret = bind(fd, (struct sockaddr *) &addr, sizeof(addr)); // On lie la socket à l'adresse
    if (ret == -1) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    ret = listen(fd, 1); // On met la socket en écoute
    if (ret == -1) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    return fd;


}


/*
 * Cette fonction permet de créer la socket de discussion 'client' en pear to pear pour le transfert de fichier
 */

int create_filetransfert_socket_connect(char ip[16], char port[6]) {

    int fd = socket(AF_INET, SOCK_STREAM, 0); // Création de la socket
    if (fd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET; // On utilise IPv4
    addr.sin_port = htons(atoi(port)); // On convertit le port
    inet_aton(ip, &addr.sin_addr); // On convertit l'adresse IP

    int ret = connect(fd, (struct sockaddr *) &addr, sizeof(addr)); // On se connecte au serveur
    if (ret == -1) {
        perror("connect");
        exit(EXIT_FAILURE);
    }

    return fd;
}

/*
 * Fonction qui envoi au serveur le struct message
 */

void send_struct(struct message *message, int serverfd) {

    char *message_ptr = (char *) message;

    ssize_t data = send_data(serverfd, message_ptr, sizeof(struct message)); // Envoi du struct message

    if (data <= 0) {
        perror("send struct");
        exit(EXIT_FAILURE);
    }

}


/*
 * Fonction qui permet d'accepter un transfert de fichier
 */
void accept_transfer(int serverfd, char *filename, char *sender) {

    printf("You accepted the file transfer.\n");

    char ip[16] = "127.0.0.1"; // on met l'ip du client qui va écouter le transfert de fichier
    char port[6] = "8085"; // on met le port du client qui va écouter le transfert de fichier

    // nota : on a choisit arbitrairement l'ip et le port du client qui va écouter le transfert de fichier
    // dans un vrai programme on devrait avoir une fonction qui choisi un port et recupere l'ip currente libre


    char *listening_file_addr_str = safe_malloc(sizeof(char) * (strlen(ip) + strlen(port) + 2)); // +2 pour le ':' et le '\0'
    strcpy(listening_file_addr_str, ip);
    strcat(listening_file_addr_str, ":");
    strcat(listening_file_addr_str, port);

    int listening_file_addr_len = strlen(listening_file_addr_str);

    // Création du struct message
    struct message msgstruct;
    msgstruct.pld_len = listening_file_addr_len;
    strncpy_safe(msgstruct.nick_sender, USERNAME, NICK_LEN);
    msgstruct.type = FILE_ACCEPT;
    strncpy_safe(msgstruct.infos, sender, INFOS_LEN);

    // Envoi du struct message
    send_struct(&msgstruct, serverfd);

    // Envoi de l'adresse du client qui va écouter le transfert de fichier
    ssize_t sent = send_data(serverfd, listening_file_addr_str, listening_file_addr_len);

    if (sent <= 0) {
        perror("send");
        exit(EXIT_FAILURE);
    }

    free(listening_file_addr_str);


    // On crée la socket de discussion en pear to pear

    int fd = create_filetransfert_socket_listen(ip, port);

    // on accepte la connexion du client qui va envoyer le fichier

    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    int fd_client = accept(fd, (struct sockaddr *) &addr, &addr_len); // On accepte la connexion entrante
    if (fd_client == -1) {
        perror("accept");
        exit(EXIT_FAILURE);
    }

    // recoit le struct file_send
    struct message file_send_struct;
    receive_data(fd_client, (char *) &file_send_struct, sizeof(struct message));

    // ACK
    struct message ack_struct;
    ack_struct.pld_len = -1;
    strncpy_safe(ack_struct.nick_sender, USERNAME, NICK_LEN);
    ack_struct.type = FILE_ACK;

    if (file_send_struct.type != FILE_SEND || file_send_struct.pld_len == -1){ // si le struct file_send n'est pas valide ou qu'il n'y a pas de fichier à recevoir
        printf("Error : FILE_SEND struct.\n");
        strncpy_safe(ack_struct.infos, "error", INFOS_LEN);
        send_struct(&ack_struct, fd_client); // on envoi un ack au client pour lui indiquer que l'on a une erreur
        close(fd_client); // fermer la socket de discussion
        return;
    };


    if (receive_file(fd_client, filename, file_send_struct.pld_len ) == 0) { // on reçoit le fichier et on s'assure de recevoir la totalité du fichier
        printf("File received successfully.\n");

        // on envoi un ack au client pour lui indiquer que l'on a bien reçu le fichier
        strncpy_safe(ack_struct.infos, filename, INFOS_LEN);


    } else {
        printf("Error while receiving file.\n"); // si il y a une erreur lors de la réception du fichier
        strncpy_safe(ack_struct.infos, "error", INFOS_LEN); // on envoi un ack au client pour lui indiquer que l'on a une erreur

    }

    send_struct(&ack_struct, fd_client); // on envoi l'ack au client

    close(fd_client); // fermer la socket de discussion


}

/*
 * Fonction qui permet de refuser un transfert de fichier
 */
void reject_transfer(int serverfd, char *filename, char *sender) {

    printf("You rejected the file transfer.\n");
    // Création du struct message
    struct message msgstruct;
    msgstruct.pld_len = -1;
    strncpy_safe(msgstruct.nick_sender, USERNAME, NICK_LEN);
    msgstruct.type = FILE_REJECT;
    strncpy_safe(msgstruct.infos, sender, INFOS_LEN);

    // Envoi du struct message
    send_struct(&msgstruct, serverfd);


}

/*
 * Cette fonction va etre lancé sur un autre thread. Elle va s'occuper de toutes les réceptions de données inopinées
 * (c'est à dire les messages envoyés par le serveur)
 * Elle va donc recevoir les messages et les afficher
 *
 * Elle va également gérer les transferts de fichiers
 */

void receive_messages(int serverfd) {
    struct pollfd fds[1];
    fds[0].fd = serverfd;
    fds[0].events = POLLIN;

    while (1) {
        int ret = poll(fds, 1, -1); // On attend qu'un événement se produise sur la socket

        if (ret == -1) {
            perror("poll");
            exit(EXIT_FAILURE);
        }

        if (fds[0].revents & POLLIN) { // Si on peut lire sur la socket

            struct message msgstruct;
            ssize_t received = receive_data(serverfd, (char *) &msgstruct, sizeof(struct message)); // On reçoit le struct message

            if (received <= 0) {
                perror("recv");
                exit(EXIT_FAILURE);
            }

            char sender[NICK_LEN + 1] = {0};
            strncpy_safe(sender, msgstruct.nick_sender, NICK_LEN);


            switch (msgstruct.type) { // On traite le message en fonction de son type
                case ECHO_SEND: { // Si c'est un message de type ECHO_SEND
                    int len = msgstruct.pld_len;
                    char *buffer = safe_malloc((len + 1) * sizeof(char));

                    received = receive_data(serverfd, buffer, len); // On reçoit le message

                    printf("Echo Message received : %s\n", buffer);  // On affiche le message
                    break;
                }
                case NICKNAME_NEW: { // Si c'est un message de type NICKNAME_NEW
                    if (strcmp(msgstruct.infos, "already used") == 0) { // Si le pseudo est déjà utilisé
                        printf("Username already taken, try again /nick \n"); // On affiche un message d'erreur
                    } else { // Sinon
                        printf("New username : %s\n", USERNAME); // On affiche le nouveau pseudo

                    }

                    break;
                }

                case NICKNAME_LIST: { // Si c'est un message de type NICKNAME_LIST
                    int len = msgstruct.pld_len;
                    char *user_list = safe_malloc((len + 1) * sizeof(char));

                    // On reçoit la liste utilisateur
                    received = receive_data(serverfd, user_list, len);

                    if (received <= 0) {
                        perror("recv");
                        exit(EXIT_FAILURE);
                    }

                    printf("%s\n", user_list); // On affiche la liste utilisateur
                    free(user_list);

                    break;
                }

                case NICKNAME_INFOS: { // Si c'est un message de type NICKNAME_INFOS
                    int len = msgstruct.pld_len;
                    char *user_info = safe_malloc((len + 1) * sizeof(char));
                    memset(user_info, 0, len + 1);

                    receive_data(serverfd, user_info, len); // On reçoit les informations sur l'utilisateur

                    printf("%s\n", user_info); // On affiche les informations

                    free(user_info);

                    break;
                }
                case BROADCAST_SEND: // Si c'est un message de type BROADCAST_SEND
                case UNICAST_SEND: { // Si c'est un message de type UNICAST_SEND

                    int msg_len = msgstruct.pld_len;
                    char *message_content = safe_malloc((msg_len + 1) * sizeof(char));
                    memset(message_content, 0, msg_len + 1);

                    receive_data(serverfd, message_content, msg_len); // On reçoit le message

                    printf("[%s]: %s\n", sender, message_content); // On affiche le message

                    free(message_content);

                    break;
                }
                case MULTICAST_CREATE: { // Si c'est un message de type MULTICAST_CREATE
                    if (strcmp(msgstruct.infos, "already used") == 0) { // Si le channel existe déjà
                        printf("Error : this channel already exist !\n"); // On affiche un message d'erreur
                    } else { // Sinon

                        // On quitte le channel actuel
                        if (strcmp(CURRENT_CHANNEL, "") == 0) {
                            struct message quit_msg;
                            quit_msg.pld_len = -1;
                            strncpy_safe(quit_msg.nick_sender, USERNAME, NICK_LEN);
                            quit_msg.type = MULTICAST_QUIT;
                            strncpy_safe(quit_msg.infos, CURRENT_CHANNEL, INFOS_LEN);
                            send_struct(&quit_msg, serverfd);
                        }


                        printf("You have created channel : %s\n", CURRENT_CHANNEL);


                        // Lorsque l'on crée un channel on le rejoint automatiquement

                        struct message channel_join;
                        channel_join.pld_len = -1;
                        strncpy_safe(channel_join.nick_sender, USERNAME, NICK_LEN);
                        channel_join.type = MULTICAST_JOIN;
                        strncpy_safe(channel_join.infos, CURRENT_CHANNEL, INFOS_LEN);

                        send_struct(&channel_join, serverfd);

                        // On aurait pu réutiliser le code de MULTICAST_JOIN mais on a préféré faire un struct message différent pour plus de clarté

                    }
                    break;
                }
                case MULTICAST_LIST: { // Si c'est un message de type MULTICAST_LIST
                    int len = msgstruct.pld_len;
                    char *channel_list = safe_malloc((len + 1) * sizeof(char));

                    // On reçoit la liste utilisateur
                    received = receive_data(serverfd, channel_list, len);

                    if (received <= 0) {
                        perror("recv");
                        exit(EXIT_FAILURE);
                    }
                    printf("%s\n", channel_list);
                    free(channel_list);
                    break;
                }
                case MULTICAST_JOIN: { // Si c'est un message de type MULTICAST_JOIN
                    char *payload = safe_malloc((msgstruct.pld_len + 1) * sizeof(char));
                    memset(payload, 0, msgstruct.pld_len + 1);

                    ssize_t payload_received = receive_data(serverfd, payload, msgstruct.pld_len); // On reçoit le message
                    if (payload_received <= 0) {
                        perror("recv");
                        free(payload);
                        exit(EXIT_FAILURE);
                    }
                    if (strcmp(payload, "[Server] channel not found !") == 0 ||
                        strcmp(payload, "[Server] You were not in the channel.") == 0) { // Si le channel n'existe pas ou que l'on n'est pas dans le channel
                        printf("%s\n", payload); // On affiche un message d'erreur
                    } else { // Sinon
                        printf("You have successfully joined the channel %s.\n", msgstruct.infos); // On affiche le channel que l'on a rejoint
                        strncpy_safe(CURRENT_CHANNEL, msgstruct.infos, INFOS_LEN); // On met à jour le channel actuel

                    }

                    free(payload);
                    break;
                }

                case MULTICAST_QUIT: { // Si c'est un message de type MULTICAST_QUIT

                    char *payload = safe_malloc((msgstruct.pld_len + 1) * sizeof(char));
                    memset(payload, 0, msgstruct.pld_len + 1);

                    ssize_t payload_received = receive_data(serverfd, payload, msgstruct.pld_len); // On reçoit le message
                    if (payload_received <= 0) {
                        perror("recv");
                        free(payload);
                        exit(EXIT_FAILURE);
                    }
                    if (strcmp(payload, "[Server] channel not found !") == 0) { // Si le channel n'existe pas
                        printf("Error: %s\n", payload); // On affiche un message d'erreur
                    } else { // Sinon
                        printf("%s\n", payload); // On affiche le message
                        strncpy_safe(CURRENT_CHANNEL, "", INFOS_LEN); // On reset le channel actuel
                    }

                    free(payload);
                    break;
                }
                case MULTICAST_SEND: { // Si c'est un message de type MULTICAST_SEND
                    char *channel_name = msgstruct.infos;

                    int msg_len = msgstruct.pld_len;
                    char *message_content = safe_malloc((msg_len + 1) * sizeof(char));
                    memset(message_content, 0, msg_len + 1);

                    receive_data(serverfd, message_content, msg_len); // On reçoit le message

                    printf("[%s]> %s> : %s\n", channel_name, sender, message_content); // On affiche le message

                    free(message_content);

                    break;
                }
                case MULTICAST_INFO: { // Si c'est un message de type MULTICAST_INFO

                    char *channel_name = msgstruct.infos;

                    int msg_len = msgstruct.pld_len;
                    char *message_content = safe_malloc((msg_len + 1) * sizeof(char));
                    memset(message_content, 0, msg_len + 1);

                    receive_data(serverfd, message_content, msg_len); // On reçoit le message

                    if (strcmp(message_content, "join") == 0) { // Si le message est de type join
                        printf("[%s] INFO> %s> has joined the channel\n", channel_name, sender); // On affiche le message de join
                    } else if (strcmp(message_content, "quit") == 0) { // Si le message est de type quit
                        printf("[%s] INFO> %s> has left the channel\n", channel_name, sender); // On affiche le message de quit

                    }
                    free(message_content);

                    break;
                }
                case FILE_REQUEST: { // Si c'est un message de type FILE_REQUEST

                    char *payload = safe_malloc((msgstruct.pld_len + 1) * sizeof(char));
                    memset(payload, 0, msgstruct.pld_len + 1);

                    ssize_t payload_received = receive_data(serverfd, payload, msgstruct.pld_len); // On reçoit le message
                    if (payload_received <= 0) {
                        perror("recv");
                        free(payload);
                        exit(EXIT_FAILURE);
                    }

                    if (strcmp(payload, "[Server] user not found !") == 0) { // Si l'utilisateur n'existe pas
                        printf("%s\n", payload); // On affiche un message d'erreur
                        free(payload);
                        break; // On quitte la fonction
                    }


                    /*
                     * Comme nous sommes dans le cas d'un bi-thread : le main thread qui lit l'entrée standard
                     * et envoi les messages au serveur et le thread qui écoute les messages inopinés,
                     * nous ne pouvons pas faire de read sur le stdin ici.
                     *
                     * La stratégie est donc la suivante :
                     * Le main thread (qui lit l'entrée standard) va mettre à jour la variable latest_char si
                     * ici on est dans le cas d'un transfert de fichier.
                     */

                    file_need_response = true; // on met la variable à true pour indiquer au main thread qu'il doit attendre une réponse
                    printf("%s wants to send you the file : '%s'. Do you want to accept ? [Y/N]\n", sender, payload);

                    while (file_need_response); // permet d'attendre que le main thread mette à jour la variable latest_char

                    char response = latest_char; // on récupère la réponse du main thread

                    file_need_response = false; // on remet la variable à false


                    if (response == 'Y' || response == 'y') { // si l'utilisateur accepte le transfert de fichier
                        accept_transfer(serverfd, payload, sender);

                    } else if (response == 'N' || response == 'n') { // si l'utilisateur refuse le transfert de fichier
                        reject_transfer(serverfd, payload, sender);

                    } else { // si l'utilisateur entre autre chose que 'Y' ou 'N'
                        printf("Please enter either 'Y' or 'N', nothing else.\n");
                    }
                    free(payload);
                    break;

                }
                case FILE_REJECT: { // Si c'est un message de type FILE_REJECT

                    printf("%s cancelled file transfer.\n", sender);
                    // on renitialise la variable globale du nom du fichier
                    memset(FILENAME, 0, INFOS_LEN);
                    break;

                }
                case FILE_ACCEPT: { // Si c'est un message de type FILE_ACCEPT

                    printf("%s accepted file transfert.\n", sender);

                    char *payload = safe_malloc((msgstruct.pld_len + 1) * sizeof(char));
                    memset(payload, 0, msgstruct.pld_len + 1);

                    ssize_t payload_received = receive_data(serverfd, payload, msgstruct.pld_len); // On reçoit le message

                    if (payload_received <= 0) {
                        perror("recv");
                        free(payload);
                        exit(EXIT_FAILURE);
                    }

                    // extraction de l'ip et du port on peut faire une fct pour ça
                    char ip[16];
                    char port[6];

                    char *token = strtok(payload, ":");

                    if (token != NULL) {
                        strcpy(ip, token);

                        token = strtok(NULL, ":");
                        if (token != NULL) {
                            strcpy(port, token);
                        } else {
                            goto invalid_ipport;
                        }
                    } else {
                        invalid_ipport:
                        printf("Invalid ip:port format.\n");
                        free(payload);
                        break;
                    }

                    ////

                    free(payload);

                    // On crée la socket de discussion en pear to pear
                    int fd = create_filetransfert_socket_connect(ip, port);


                    // on envoie un stuct file_send pour indiquer au client que l'on va envoyer un fichier

                    struct message file_send_struct;
                    strncpy_safe(file_send_struct.nick_sender, USERNAME, NICK_LEN);
                    file_send_struct.type = FILE_SEND;
                    file_send_struct.pld_len = getfilesize(FILENAME);
                    strncpy_safe(file_send_struct.infos, FILENAME, INFOS_LEN);

                    send_struct(&file_send_struct, fd);



                    // On envoie le fichier et on s'assure de recevoir l'ack du client

                    if (send_file(fd, FILENAME) == 0) {


                        struct message ack_struct;
                        receive_data(fd, (char *) &ack_struct, sizeof(struct message)); // On reçoit l'ack du client

                        if (ack_struct.type == FILE_ACK && strcmp(ack_struct.infos, FILENAME) == 0) { // Si l'ack est valide
                            printf("File sent successfully.\n");
                        } else { // Si l'ack n'est pas valide
                            printf("Error while sending file.\n");
                        }

                    } else {
                        printf("Error while sending file.\n");
                    }

                    // renitialisation de la variable globale du nom du fichier
                    memset(FILENAME, 0, INFOS_LEN);

                    // fermer la socket de discussion
                    close(fd);

                    break;
                }

                default:
                    printf("The message received is an unknown type \n");
                    break;

            }

        }
    }
}


/*
 * Fonction qui va lire la ligne de commande
 */
void handle_command(char *buff, int serverfd) {

    // Différencier le type de commandes
    char **argv = buff_to_argv_like(buff);
    char *commande = argv[0];

    // Si c'est une commande de type /nick
    if (strcmp(commande, "/nick") == 0) {
        if (argv[1] == NULL) {
            printf("Please enter an username\n");
            return;
        }

        if (isInvalidUsername(argv[1]) == false) { // si le pseudo est valide
            strncpy_safe(USERNAME, argv[1], NICK_LEN); // on met à jour le pseudo
            // création du struct message
            struct message username_msg;
            username_msg.pld_len = -1;
            strncpy_safe(username_msg.nick_sender, "", NICK_LEN);
            username_msg.type = NICKNAME_NEW;
            strncpy_safe(username_msg.infos, argv[1], INFOS_LEN);

            send_struct(&username_msg, serverfd); // on envoi le struct message au serveur
        }

    } else if (strcmp(commande, "/quit") == 0) { // si c'est une commande de type /quit


        if (argv[1] == NULL) {  // si on veut quitter le server 

            // création du struct message
            struct message quit_msg;
            quit_msg.pld_len = -1;
            strncpy_safe(quit_msg.nick_sender, USERNAME, NICK_LEN);
            quit_msg.type = ECHO_SEND;
            strncpy_safe(quit_msg.infos, CURRENT_CHANNEL, INFOS_LEN);

            send_struct(&quit_msg, serverfd);
            exit(EXIT_SUCCESS);
        } else {   //si on veut quitter un channel

            if (strcmp(argv[1], CURRENT_CHANNEL) != 0) { // si on est pas dans le channel que l'on veut quitter
                printf("You are not currently in this channel ! \n");
                return;
            }

            // création du struct message
            struct message quit_msg;
            quit_msg.pld_len = -1;
            strncpy_safe(quit_msg.nick_sender, USERNAME, NICK_LEN);
            quit_msg.type = MULTICAST_QUIT;
            strncpy_safe(quit_msg.infos, CURRENT_CHANNEL, INFOS_LEN);

            send_struct(&quit_msg, serverfd);

        }

    } else if (strcmp(commande, "/who") == 0) { // si c'est une commande de type /who

        struct message who_msg;
        who_msg.pld_len = -1;
        strncpy_safe(who_msg.nick_sender, USERNAME, NICK_LEN);
        who_msg.type = NICKNAME_LIST;
        strncpy_safe(who_msg.infos, "", INFOS_LEN);

        send_struct(&who_msg, serverfd); // on envoi le struct message au serveur

    } else if (strcmp(commande, "/whois") == 0) { // si c'est une commande de type /whois

        if (argv[1] == NULL) { // si on a pas entré d'username
            printf("Please enter an username \n");
            return;
        }

        struct message username_msg;
        username_msg.pld_len = -1;
        strncpy_safe(username_msg.nick_sender, USERNAME, NICK_LEN);
        username_msg.type = NICKNAME_INFOS;
        strncpy_safe(username_msg.infos, argv[1], INFOS_LEN);

        send_struct(&username_msg, serverfd); // on envoi le struct message au serveur

    } else if (strcmp(commande, "/msgall") == 0) { // si c'est une commande de type /msgall

        if (argv[1] == NULL) { // si on a pas entré de message
            printf("Please enter a message\n");
            return;
        }
        /*
         * On concatène tous les arguments de la commande pour former le message
         */
        char message_to_send[MSG_LEN] = "";
        for (int i = 1; argv[i] != NULL; i++) {
            strcat(message_to_send, argv[i]);
            if (argv[i + 1] != NULL) {
                strcat(message_to_send, " ");
            }
        }


        struct message public_msg;
        public_msg.pld_len = strlen(message_to_send);
        strncpy_safe(public_msg.nick_sender, USERNAME, NICK_LEN);
        public_msg.type = BROADCAST_SEND;
        strncpy_safe(public_msg.infos, "", INFOS_LEN);

        send_struct(&public_msg, serverfd); // on envoi le struct message au serveur
        send_data(serverfd, message_to_send, public_msg.pld_len);  // on envoi le message au serveur

    } else if (strcmp(commande, "/msg") == 0) { // si c'est une commande de type /msg

        if (argv[1] == NULL || argv[2] == NULL) { // si on a pas entré de message ou d'username
            printf("Please enter a message and an username\n");
            return;
        }
        /*
         * On concatène tous les arguments de la commande pour former le message (sauf le premier qui est l'username)
         */
        char message_to_send[MSG_LEN] = "";
        for (int i = 2; argv[i] != NULL; i++) {
            strcat(message_to_send, argv[i]);
            if (argv[i + 1] != NULL) {
                strcat(message_to_send, " ");
            }
        }

        struct message private_msg;
        private_msg.pld_len = strlen(message_to_send);
        strncpy_safe(private_msg.nick_sender, USERNAME, NICK_LEN);
        private_msg.type = UNICAST_SEND;
        strncpy_safe(private_msg.infos, argv[1], INFOS_LEN);

        send_struct(&private_msg, serverfd); // on envoi le struct message au serveur
        send_data(serverfd, message_to_send, private_msg.pld_len); // on envoi le message au serveur

    } else if (strcmp(commande, "/create") == 0) { // si c'est une commande de type /create
        if (argv[1] == NULL) { // si on a pas entré de nom de channel
            printf("Please enter the channel's name you want to create after the command \n");
            return;
        }
        if (isInvalidUsername(argv[1]) == true) { // si le nom du channel est invalide
            printf(" The channel's name is invalid : No spaces or special characters allowed \n");
        } else { // si le nom du channel est valide
            struct message channel_name;
            channel_name.pld_len = -1;
            strncpy_safe(channel_name.nick_sender, USERNAME, NICK_LEN);
            channel_name.type = MULTICAST_CREATE;
            strncpy_safe(channel_name.infos, argv[1], INFOS_LEN);

            send_struct(&channel_name, serverfd); // on envoi le struct message au serveur
            strncpy_safe(CURRENT_CHANNEL, argv[1], INFOS_LEN); // on met à jour le channel actuel
        }

    } else if (strcmp(commande, "/channel_list") == 0) { // si c'est une commande de type /channel_list

        struct message channel_list;
        channel_list.pld_len = -1;
        strncpy_safe(channel_list.nick_sender, USERNAME, NICK_LEN);
        channel_list.type = MULTICAST_LIST;
        strncpy_safe(channel_list.infos, "", INFOS_LEN);

        send_struct(&channel_list, serverfd); // on envoi le struct message au serveur

    } else if (strcmp(commande, "/join") == 0) { // si c'est une commande de type /join
        if (argv[1] == NULL) { // si on a pas entré de nom de channel
            printf("Please enter the channel's name you want to join after the command \n");
            return;
        } else { // si on a entré un nom de channel
            struct message channel_join;
            channel_join.pld_len = -1;
            strncpy_safe(channel_join.nick_sender, USERNAME, NICK_LEN);
            channel_join.type = MULTICAST_JOIN;
            strncpy_safe(channel_join.infos, argv[1], INFOS_LEN);

            send_struct(&channel_join, serverfd); // on envoi le struct message au serveur
        }
    } else if (strcmp(commande, "/send") == 0) { // si c'est une commande de type /send
        if (argv[1] == NULL || argv[2] == NULL) {
            printf("The send request has to be in that form : /send <receptor_username> <filename> \n");
            return;
        } else if (does_file_exist(argv[2]) != 1) { // si le fichier n'est pas valide
            printf("The file %s doesn't exist !\n", argv[2]);
            return;
        } else {

            // si l'utilisateur s'envoi un fichier à lui même
            if (strcmp(argv[1], USERNAME) == 0) {
                printf("You can't send a file to yourself !\n");
                return;
            }

            // copie le nom du fichier dans la variable globale
            strncpy_safe(FILENAME, argv[2], INFOS_LEN);

            struct message send_file_struct;

            int len = strlen(argv[2]);

            send_file_struct.pld_len = len;
            strncpy_safe(send_file_struct.nick_sender, USERNAME, NICK_LEN);
            send_file_struct.type = FILE_REQUEST;
            strncpy_safe(send_file_struct.infos, argv[1], INFOS_LEN); // stock le nom du recepteur dans infos

            send_struct(&send_file_struct, serverfd);
            send_data(serverfd, argv[2], len); // envoie le nom du fichier au serveur



            printf("Waiting for the response of the user %s ...\n", argv[1]);
        }
    } else {
        printf("Unknown command \n");
        return;

    }
}

/*
 * Cette fonction sert à envoyer un message au serveur le struct message + le message
 */
void send_message(char *buff, int serverfd) {

    //si le message est vide on ne fait rien
    if (strcmp(buff, "") == 0) {
        printf("Veuillez entrer un message\n");
        return;
    }


    // Création du struct message
    struct message msgstruct;
    msgstruct.pld_len = strlen(buff);
    strncpy_safe(msgstruct.nick_sender, USERNAME, NICK_LEN);
    msgstruct.type = ECHO_SEND;
    strncpy_safe(msgstruct.infos, "", INFOS_LEN);

    // Envoi du struct message
    send_struct(&msgstruct, serverfd);

    // Envoi du message
    ssize_t sent = send_data(serverfd, buff, msgstruct.pld_len);

    if (sent <= 0) {
        perror("send");
        exit(EXIT_FAILURE);
    }
}


/*
 * Cette fonction sert à recevoir un message du serveur
 */

char *receive_message(int serverfd) {

    // Création du struct message
    struct message msgstruct;


    // Reception du struct message

    ssize_t received = receive_data(serverfd, (char *) &msgstruct, sizeof(struct message));

    if (received <= 0) {
        perror("recv");
        exit(EXIT_FAILURE);
    }

    // Création du buffer
    char *buff = safe_malloc((msgstruct.pld_len + 1) * sizeof(char));


    // Reception du message

    received = receive_data(serverfd, buff, msgstruct.pld_len);

    if (received <= 0) {
        perror("recv");
        exit(EXIT_FAILURE);
    }

    buff[msgstruct.pld_len] = '\0';
    return buff;
}

/*
 * Cette fonction sert à se connecter au serveur
 */
int handle_connect(const char *server_name, const char *server_port) {
    struct addrinfo hints, *result, *rp;
    int sfd;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(server_name, server_port, &hints, &result) != 0) {
        perror("getaddrinfo()");
        exit(EXIT_FAILURE);
    }
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd == -1) {
            continue;
        }
        if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1) {
            break;
        }
        close(sfd);
    }
    if (rp == NULL) {
        fprintf(stderr, "Could not connect\n");
        exit(EXIT_FAILURE);
    }
    freeaddrinfo(result);
    return sfd;
}

int main(int argc, char *argv[]) {
    // Dans le terminal 2 arguments vont être entré, le numéro de port et le nom du server

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <server_name> <server_port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *server_name = argv[1];
    const char *server_port = argv[2];
    int sfd;
    sfd = handle_connect(server_name, server_port); // On se connecte au serveur


    if (sfd != -1) { // Si la connexion est réussie

        printf("Connecting to server ... done!\n");
        printf("Please log in with /nick <your pseudo>\n");

        // On lance le thread qui va écouter les messages inopinés
        pthread_t listener_thread;
        pthread_create(&listener_thread, NULL, (void *) receive_messages, (void *) (intptr_t) sfd);

        while (1) { // On lit l'entrée standard et on envoi les messages au serveur

            /*
             * On utilise fgets pour lire l'entrée standard car on veut lire une ligne entière
             */
            char buff[MSG_LEN] = {0};
            fgets(buff, sizeof(buff), stdin);
            buff[strcspn(buff, "\n")] = '\0';

            if (file_need_response == true) {  // si on est dans le cas d'un transfert de fichier
                strcpy(&latest_char, &buff[0]); // on met à jour la variable globale latest_char
                file_need_response = false; // on met la variable globale file_need_response à false
                continue; // on passe à la suite de la boucle
            }
            if (buff[0] == '/') { // Si le message commence par un '/' c'est une commande
                handle_command(buff, sfd); // On traite la commande

            } else if (USERNAME[0] != '\0') { // sinon c'est un message normal et on vérifie que l'on a bien un pseudo

                if (CURRENT_CHANNEL[0] != '\0') {    // Si on est dans un channel on envoie le message au channel

                    struct message public_msg;
                    public_msg.pld_len = strlen(buff);
                    strncpy_safe(public_msg.nick_sender, USERNAME, NICK_LEN);
                    public_msg.type = MULTICAST_SEND;
                    strncpy_safe(public_msg.infos, CURRENT_CHANNEL, INFOS_LEN);

                    send_struct(&public_msg, sfd);
                    send_data(sfd, buff, public_msg.pld_len);


                } else {
                    send_message(buff, sfd);         // sinon c'est un messsage normal
                }
            } else {
                printf("Please enter an username\n");

            }


        }


    }
    close(sfd);

    return EXIT_SUCCESS;
}

