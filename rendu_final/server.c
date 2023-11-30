#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <poll.h>
#include "common.h"
#include "msg_struct.h"
#include "time.h"
#include <ctype.h>

#define MAX_CLIENTS 10


/*
 * Structure qui permet de stocker un message et son payload
 */
struct wrapped_message {
    struct message msg;
    char *payload;
};

/*
 * Gestion du client et des listes chainées.
 */
struct client_info {
    int sockfd;
    struct sockaddr_in address;
    char nickname[NICK_LEN];
    time_t connect_time;
    struct client_info *next;
};

/*
 * Gestion des channels et des listes chainées.
 */
struct channel_info {
    char name[NICK_LEN];
    struct client_info **clients_head;
    struct channel_info *next;
};


/*
 * Fonction qui permet de faire des mallocs proprement
 */
void *safe_malloc(size_t size) {
    void *ptr = malloc(size);
    if (!ptr) {
        free(ptr);
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

/*
 * Fonction qui permet de faire des strncpy sans risque de dépassement tampon
 */
void strncpy_safe(char *dest, const char *src, size_t dest_size) {
    if (dest_size == 0) return;

    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';
}


/*
 * Fonction qui permet de recevoir des données
 */
ssize_t receive_data(int sockfd, void *buffer, size_t length) {
    ssize_t total_bytes_received = 0;
    while (total_bytes_received < length) {
        ssize_t bytes_received = recv(sockfd, (char *) buffer + total_bytes_received,
                                      length - total_bytes_received, 0);

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
ssize_t send_data(int sockfd, const void *buffer, size_t length) {
    if (strcmp(buffer, "\0") == 0) {
        return 0;
    }

    ssize_t total_bytes_sent = 0;
    while (total_bytes_sent < length) {
        ssize_t bytes_sent = send(sockfd, (char *) buffer + total_bytes_sent,
                                  length - total_bytes_sent, 0);

        if (bytes_sent <= 0) {
            return bytes_sent;
        }

        total_bytes_sent += bytes_sent;
    }
    return total_bytes_sent;
}


/*
 * Fonction qui vérifie si un username est déjà pris.
 */
int is_username_taken(struct client_info **head, char *new_nickname) {
    struct client_info *current = *head;
    while (current != NULL) {
        if (strncmp(current->nickname, new_nickname, NICK_LEN) == 0) {
            return 1; // Vrai , le username est déjà pris
        }
        current = current->next;
    }
    return -1; // Faux , le username est disponible
}


/*
 * Met à jour le nickname d'un client.
 * on vérifie cependant que le nouveau nickname n'est pas déjà utilisé
 * on renvoie -1 si c'est deja utilisé -2 si le client n'est pas trouvé et 1 si tout s'est bien passé
 */
int update_nickname(int sockfd, struct client_info **head, char *new_nickname) {

    if (is_username_taken(head, new_nickname) == 1) {
        return -1; // Retourner -1 pour indiquer que le username est déjà pris
    }

    struct client_info *current = *head;
    while (current != NULL) { // Parcourir la liste chainée
        if (current->sockfd == sockfd) { // Le client à mettre à jour est trouvé
            strncpy_safe(current->nickname, new_nickname, NICK_LEN); // Mettre à jour le nickname
            return 1; // Retourner 1 pour indiquer que tout s'est bien passé
        }
        current = current->next; // Passer au client suivant
    }
    return -2; // Retourner -2 pour indiquer que le client n'a pas été trouvé
}


/*
 * Fonction qui compte le nombre de clients connectés
 */
int count_online_users(struct client_info **client_list) {
    int count = 0;
    struct client_info *current = *client_list;

    while (current != NULL) { // Parcourir la liste chainée
        count++; // Incrémenter le compteur
        current = current->next; // Passer au client suivant
    }

    return count;
}


/*
 * Fonction qui renvoie un char* contenant le message de la listes des utilisateurs en lignes
 *
 */
char *get_online_users(struct client_info **client_list) {

    int nb_users = count_online_users(client_list); // Compter le nombre d'utilisateurs en ligne


    char srv_msg_annoucer[] = "[Server] : Online users are\n";
    char srv_msg_blank[] = "                          - ";


    // la formule permet de calculer la taille de la chaine de caractère
    char *user_list = safe_malloc(
            strlen(srv_msg_annoucer) + nb_users * (strlen(srv_msg_blank) + NICK_LEN + 1)); // +1 pour le \n


    strcpy(user_list, srv_msg_annoucer); // Copier le message d'annonce dans la liste des utilisateurs

    struct client_info *current = *client_list;
    while (current != NULL) { // Parcourir la liste chainée
        /*
         * Concaténer le nom de l'utilisateur actuel à la liste des utilisateurs
         */
        strcat(user_list, srv_msg_blank);
        strcat(user_list, current->nickname);
        strcat(user_list, "\n");
        current = current->next; // Passer au client suivant
    }

    return user_list; // Retourner la liste des utilisateurs
}

/*
 *  Fonction qui renvoie les informations relatives à un utilisateur
 */
char *get_user_infos(struct client_info *client) {

    char *user_infos = safe_malloc((150 + NICK_LEN) * sizeof(char)); // 150 est la taille de la chaine de caractère


    struct tm *tm_info = localtime(&client->connect_time); // Récupérer la date de connexion du client
    char time_str[25]; // Chaine de caractère pour stocker la date de connexion
    strftime(time_str, sizeof(time_str), "%Y/%m/%d@%H:%M", tm_info); // Formater la date de connexion

    char *ip_address = inet_ntoa(client->address.sin_addr); // Récupérer l'adresse IP du client

    int port_number = ntohs(client->address.sin_port); // Récupérer le numéro de port du client

    sprintf(user_infos, "[Server] : %s connected since %s with IP address %s and port number %d",
            client->nickname, time_str, ip_address, port_number); // Formater les informations du client

    return user_infos;
}


/*
 * Ajoute un client à la liste chainée.
 */
void add_client(int sockfd, struct sockaddr_in address, struct client_info **head) {
    struct client_info *new_client = (struct client_info *) safe_malloc(sizeof(struct client_info));


    new_client->sockfd = sockfd;
    new_client->address = address;
    new_client->next = *head;
    strncpy_safe(new_client->nickname, "anonymous", NICK_LEN); // Initialiser le nickname à "anonymous"
    new_client->connect_time = time(NULL); // Initialiser la date de connexion à la date actuelle
    *head = new_client; // Mettre à jour la tête de la liste chainée
}

/*
 * Supprime un client de la liste chainée.
 */
void remove_client(int sockfd, struct client_info **head) {
    struct client_info *current = *head;
    struct client_info *prev = NULL;

    while (current != NULL) { // Parcourir la liste chainée
        if (current->sockfd == sockfd) { // Le client à supprimer est trouvé
            if (prev == NULL) { // Le client à supprimer est la tête de la liste
                *head = current->next; // Mettre à jour la tête de la liste
            } else { // Le client à supprimer n'est pas la tête de la liste
                prev->next = current->next; // Mettre à jour le pointeur next du client précédent
            }
            free(current);
            return;
        }
        prev = current;
        current = current->next;
    }
}

/*
 * Renvoie un client de la liste chainée.
 */
struct client_info *get_client(int sockfd, struct client_info **head) {
    struct client_info *current = *head;
    while (current != NULL) { // Parcourir la liste chainée
        if (current->sockfd == sockfd) {  // Le client est trouvé
            return current;  // Retourner le client
        }
        current = current->next; // Passer au client suivant
    }
    return NULL; // Retourner NULL si le client n'est pas trouvé
}

/*
 * Renvoie un client de la liste chainée par rapport à son nickname
 */

struct client_info *get_client_by_nickname(char *nickname, struct client_info **head) {

    struct client_info *current = *head;
    while (current != NULL) { // Parcourir la liste chainée
        if (strcmp(current->nickname, nickname) == 0) { // Le client est trouvé
            return current; // Retourner le client
        }
        current = current->next; // Passer au client suivant
    }
    return NULL; // Retourner NULL si le client n'est pas trouvé
}


/*
 * cette fonction reçoit les structs message
 */
struct wrapped_message *receive_msg(int sockfd, struct client_info **client_list) {

    struct wrapped_message *w_msg = (struct wrapped_message *) safe_malloc(
            sizeof(struct wrapped_message));  //allocation de la mémoire pour le struct message
    w_msg->payload = NULL;

    // Recoit le struct header
    ssize_t bytes_received = receive_data(sockfd, (char *) &(w_msg->msg), sizeof(struct message));

    if (bytes_received <= 0) { // Si le nombre d'octets reçus est inférieur ou égal à 0, il y a eu une erreur
        goto handle_disconnection; // Gestion de la déconnexion et libération de la mémoire
    }

    // si le message contient un payload, on le recoit
    if (w_msg->msg.pld_len > 0) {
        w_msg->payload = (char *) safe_malloc(w_msg->msg.pld_len + 1); // +1 pour le \0

        bytes_received = receive_data(sockfd, w_msg->payload, w_msg->msg.pld_len); // Recevoir le payload

        if (bytes_received <= 0) { // Si le nombre d'octets reçus est inférieur ou égal à 0, il y a eu une erreur
            goto handle_disconnection; // Gestion de la déconnexion et libération de la mémoire
        }

        w_msg->payload[w_msg->msg.pld_len] = '\0'; // \0 à la fin du payload pour s'assurer qu'il est bien terminé
    }

    return w_msg;

    handle_disconnection:
    // Gestion de la déconnexion et libération de la mémoire
    {
        struct client_info *client = get_client(sockfd, client_list); // Récupérer le client
        if (client != NULL) { // Si le client est trouvé
            printf("Déconnexion de : %s\n", client->nickname);  // Afficher le nickname du client
        } else {
            printf("Déconnexion d'un client inconnu\n"); // Afficher un message d'erreur
        }

        remove_client(sockfd, client_list); // Retirer le client de la liste chainée
        close(sockfd); // Fermer le socket
        if (w_msg->payload) { // Libérer le payload si nécessaire
            free(w_msg->payload);
        }
        free(w_msg); // Libérer le struct message
        return NULL;
    }
}

/*
 * Fonction qui envoi au serveur le struct message
 */

void send_struct(struct message *message, int serverfd) {

    if (message == NULL) {
        return;
    }

    ssize_t sent = send_data(serverfd, message, sizeof(struct message));

    if (sent <= 0) {
        perror("send struct");
        return;
    }

}

void send_wrapped_message(int sockfd, struct wrapped_message *w_msg) {
    send_struct(&(w_msg->msg), sockfd);
    if (w_msg->msg.pld_len > 0) { // Si le message contient un payload, l'envoyer
        ssize_t send = send_data(sockfd, w_msg->payload, w_msg->msg.pld_len);
        if (send <= 0) { // Si le nombre d'octets envoyés est inférieur ou égal à 0, il y a eu une erreur
            perror("send");
            return;
        }
    }
}

/*
 * Fonction qui permet de créer un message serveur
 */
struct message create_server_message(enum msg_type type, const char *infos) {
    struct message msg;
    memset(&msg, 0, sizeof(msg)); // Initialiser le message à 0

    if (strlen(infos) == 0) { // Si le message ne contient pas d'informations, mettre le premier caractère à \0
        msg.infos[0] = '\0';

    }

    msg.pld_len = -1; // -1 pour indiquer qu'il n'y a pas de payload
    strncpy_safe(msg.nick_sender, "Server", NICK_LEN); // Mettre le nickname à "Server"
    msg.type = type; // Mettre le type du message

    if (infos != NULL) { // Si le message contient des informations, les copier
        strncpy_safe(msg.infos, infos, INFOS_LEN);
    }


    return msg; // Retourner le message
}


/*
 * Vérifie si le nom du salon est valide
 */
int is_valid_channel_name(char *name) {
    // Vérification de la validité du nom du salon (pas d'espaces, pas de caractères spéciaux, etc.)
    for (int i = 0; name[i] != '\0'; i++) {
        if (!isalnum(name[i]) && name[i] != '_') {
            return 0; // Nom du salon invalide
        }
    }
    return 1; // Nom du salon valide
}


/*
 * renvoie un channel par rapport à son nom
 */
struct channel_info *get_channel_by_name(char *name, struct channel_info **channel_heads) {

    struct channel_info *current = *channel_heads;
    while (current != NULL) { // Parcourir la liste chainée
        if (strcmp(current->name, name) == 0) { // Le canal est trouvé
            return current; // Retourner le canal
        }
        current = current->next; // Passer au canal suivant
    }
    return NULL; // Retourner NULL si le canal n'est pas trouvé
}

/*
 * création d'un channel renvoie -1 si le channel existe déjà et 0 si tout s'est bien passé
 */
int create_channel(char *channel_name, struct channel_info **channel_heads) {
    if (channel_heads == NULL || !is_valid_channel_name(channel_name) ||
        get_channel_by_name(channel_name, channel_heads) != NULL) {
        return -1; // Pointeur nul, nom du salon invalide ou déjà utilisé
    }

    struct channel_info *new_channel = safe_malloc(
            sizeof(struct channel_info)); // Allouer la mémoire pour le nouveau canal
    strncpy_safe(new_channel->name, channel_name, NICK_LEN); // Copier le nom du canal
    new_channel->clients_head = safe_malloc(
            sizeof(struct client_info *)); // Allouer la mémoire pour la liste des clients

    *new_channel->clients_head = NULL; // Initialiser la liste des clients à NULL
    new_channel->next = *channel_heads; // Mettre à jour la tête de la liste chainée
    *channel_heads = new_channel; // Mettre à jour la tête de la liste chainée

    printf("Channel %s created. Initializing client list to NULL.\n",
           new_channel->name); // Afficher un message de confirmation

    return 0;
}


/*
 * supprime un channel
 */
void remove_channel(struct channel_info *channel, struct channel_info **channel_heads) {
    if (channel == NULL || channel_heads == NULL) {
        return; // Retourne si l'entrée est invalide
    }

    struct channel_info *current = *channel_heads; // Pointeur vers la tête de la liste chainée
    struct channel_info *prev = NULL; // Pointeur vers le canal précédent

    while (current != NULL) { // Parcourir la liste chainée
        if (current == channel) { // Le canal à supprimer est trouvé
            if (prev == NULL) {  // Le canal à supprimer est la tête de la liste
                *channel_heads = current->next; // Mettre à jour la tête de la liste chainée
            } else {  // Le canal à supprimer n'est pas la tête de la liste
                prev->next = current->next; // Mettre à jour le pointeur next du canal précédent
            }

            // Libérer la liste des clients du canal
            if (current->clients_head != NULL) {
                free(current->clients_head);
            }

            free(current); // Libérer le canal
            break; // Sortir de la boucle après la suppression
        }
        prev = current; // Mettre à jour le canal précédent
        current = current->next; // Passer au canal suivant
    }
}

// Cette fonction vérifie si le client donné est dans la liste des clients du canal donné.
// Elle retourne 1 si le client est trouvé, 0 sinon.
int is_client_in_channel(struct client_info *client, struct channel_info *channel) {
    struct client_info *current_client = *(channel->clients_head);
    while (current_client != NULL) {
        printf("Comparing %s to %s\n", current_client->nickname, client->nickname);
        if (current_client->sockfd == client->sockfd) {
            printf("Client %s found in channel %s.\n", client->nickname, channel->name);
            return 1; // Le client est trouvé dans le canal

        }
        current_client = current_client->next;
    }
    return 0; // Le client n'est pas trouvé dans le canal
}


/*
 * ajoute un client à un channel
 */
void add_client_to_channel(struct client_info *client, struct channel_info *channel) {
    if (!client || !channel) { // Vérifier si les pointeurs sont nuls
        printf("Client or channel pointer is NULL, cannot add client to channel.\n");
        return;
    }

    // Vérifier si le client est déjà dans la liste
    if (is_client_in_channel(client, channel) == 1) {
        printf("Client %s is already in channel %s.\n", client->nickname, channel->name);
        return;
    }

    // Créer un nouveau nœud pour la liste du channel
    struct client_info *new_client_node = safe_malloc(sizeof(struct client_info));

    *new_client_node = *client;  // Copier les informations du client
    new_client_node->next = *(channel->clients_head);  // Insérer en tête de liste
    *(channel->clients_head) = new_client_node;  // Mettre à jour la tête de liste

    printf("%s successfully added to channel %s.\n", client->nickname, channel->name);
}


/*
 * supprime un client d'un channel
 */
void remove_client_from_channel(struct client_info *client, struct channel_info *channel) {

    if (!client || !channel) return; // Vérifier si les pointeurs sont nuls

    struct client_info **head = channel->clients_head; // Pointeur vers la tête de la liste chainée
    struct client_info *current = *head, *prev = NULL; // Pointeurs vers le client actuel et le client précédent

    while (current != NULL) {  // Parcourir la liste chainée
        if (current == client) { // Le client à supprimer est trouvé
            if (prev == NULL) { // Le client à supprimer est la tête de la liste
                *head = current->next; // Mettre à jour la tête de la liste chainée
            } else {  // Le client à supprimer n'est pas la tête de la liste
                prev->next = current->next; // Mettre à jour le pointeur next du client précédent
            }
            return; // Sortir de la boucle après la suppression
        }
        prev = current; // Mettre à jour le client précédent
        current = current->next; // Passer au client suivant
    }
}

/*
 * Fonction qui permet de compter le nombre de channels
 */

int count_channels(struct channel_info **channel_heads) {
    int count = 0;
    struct channel_info *current = *channel_heads;

    while (current != NULL) { // Parcourir la liste chainée
        count++; // Incrémenter le compteur
        current = current->next; // Passer au canal suivant
    }

    return count;
}


/*
 * Liste les channels existant et renvois la chaines de caractères correspondante
 */
char *list_channels(struct channel_info **channel_heads) {

    if (*channel_heads == NULL) { // Si la liste des canaux est vide, renvoyer un message
        const char *no_channels_msg = "[Server] : No channels available\n"; // Aucun canal disponible
        char *no_channels = safe_malloc(strlen(no_channels_msg) + 1); // +1 pour le \0
        strncpy_safe(no_channels, no_channels_msg, strlen(no_channels_msg) + 1); // Copier le message
        return no_channels; // Retourner le message
    }

    struct channel_info *current = *channel_heads; // Pointeur vers la tête de la liste chainée
    int nb_channels = count_channels(channel_heads); // Compter le nombre de canaux

    char srv_msg_annoucer[] = "[Server] : Available channels are:\n"; // Message d'annonce
    char srv_msg_blank[] = "                          - ";

    char *channel_list = safe_malloc(
            strlen(srv_msg_annoucer) + nb_channels * (strlen(srv_msg_blank) + NICK_LEN + 1)); // +1 pour le \0

    strcpy(channel_list, srv_msg_annoucer); // Copie le message d'annonce dans la liste des canaux

    current = *channel_heads; // Pointeur vers la tête de la liste chainée
    while (current != NULL) { // Parcourir la liste chainée
        /*
         * Concaténer le nom du canal actuel à la liste des canaux
         */
        strcat(channel_list, srv_msg_blank);
        strcat(channel_list, current->name);
        strcat(channel_list, "\n");
        current = current->next; // Passer au canal suivant
    }

    return channel_list; // Retourner la liste des canaux
}

/*
 * Fonction qui permet de gérer le channel not found suivant le type de message à renvoyer
 */

void handle_channel_not_found(struct wrapped_message *w_msg, struct client_info *client, enum msg_type type) {

    char *channel_not_found = "[Server] channel not found !"; // Message à renvoyer
    int len = strlen(channel_not_found) + 1; // Taille du message

    w_msg->msg = create_server_message(type, ""); // Créer le message de réponse
    w_msg->payload = safe_malloc(len); // +1 pour le \0
    strncpy_safe(w_msg->payload, channel_not_found, len); // Copier le message
    w_msg->msg.pld_len = strlen(w_msg->payload); // Mettre à jour la taille du payload
    send_wrapped_message(client->sockfd, w_msg); // Envoyer le message au client

}


/*
 * Fonction qui permet d'envoyer un message à tous les utilisateurs d'un canal sans le client qui a envoyé le message
 */

void send_to_channel(struct wrapped_message *w_msg, struct client_info *client, struct channel_info *channel) {

    struct client_info *current_client = *(channel->clients_head); // Pointeur vers la tête de la liste chainée
    while (current_client != NULL) { // Parcourir la liste chainée
        if (current_client->sockfd != client->sockfd) { // Ne pas envoyer au client qui a envoyé le message
            send_wrapped_message(current_client->sockfd, w_msg); // Envoyer le message au client
        }
        current_client = current_client->next; // Passer au client suivant
    }
}

/*
 * Fonction qui permet de gérer les messages
 */
void handle_message(struct wrapped_message *w_msg, struct client_info **client_list, int sockfd,
                    struct channel_info **channel_heads) {
    struct client_info *client = get_client(sockfd, client_list); // Récupérer le client
    if (client == NULL) { // Si le client n'est pas trouvé, afficher un message d'erreur
        printf("error: Client not found sockfd : %i\n", sockfd);
        return;
    }
    struct wrapped_message response;  // Initialiser le message de réponse

    memset(&response, 0, sizeof(struct wrapped_message));

    switch (w_msg->msg.type) { // Vérifier le type du message
        case NICKNAME_NEW: // Nouveau nickname

            response.msg.pld_len = -1; // -1 pour indiquer qu'il n'y a pas de payload
            strncpy_safe(response.msg.nick_sender, "Server", NICK_LEN); // Mettre le nickname à "Server"
            response.msg.type = NICKNAME_NEW; // Mettre le type du message

            char old_nickname[NICK_LEN]; // Chaine de caractère pour stocker l'ancien nickname
            strncpy_safe(old_nickname, client->nickname, NICK_LEN); // Copier l'ancien nickname
            if (update_nickname(sockfd, client_list, w_msg->msg.infos) == -1) {  // Le nickname est déjà utilisé
                strncpy_safe(response.msg.infos, "already used", INFOS_LEN); // Informer le client
                printf("[Server] : %s tried to use an already used nickname\n",
                       client->nickname); // Afficher un message
            } else { // Le nickname est disponible
                strncpy_safe(response.msg.infos, "good username", INFOS_LEN); // Informer le client
                printf("[Server] : %s changed his nickname to %s\n", old_nickname,
                       w_msg->msg.infos); // Afficher un message
            }

            send_wrapped_message(sockfd, &response); // Envoyer le message de réponse
            break;

        case ECHO_SEND: // Echo
            if (w_msg->payload) { // Si le message contient un payload
                strncpy_safe(w_msg->msg.nick_sender, "Server", NICK_LEN); // Mettre le nickname à "Server"
                send_wrapped_message(sockfd, w_msg);  // Envoyer le message au client

            }
            break;

        case NICKNAME_LIST: // Liste des utilisateurs en ligne
            response.msg = create_server_message(NICKNAME_LIST, ""); // Créer le message de réponse

            char *user_list = get_online_users(client_list); // Récupérer la liste des utilisateurs en ligne
            response.payload = user_list; // Mettre à jour le payload
            response.msg.pld_len = strlen(response.payload); // Mettre à jour la taille du payload

            send_wrapped_message(sockfd, &response); // Envoyer le message de réponse

            if (user_list != NULL) { // Libérer la liste des utilisateurs en ligne si nécessaire
                free(user_list);
            }
            break;


        case NICKNAME_INFOS: // Informations sur un utilisateur
            response.msg = create_server_message(NICKNAME_INFOS, ""); // Créer le message de réponse

            struct client_info *target_user = get_client_by_nickname(w_msg->msg.infos,
                                                                     client_list); // Récupérer le client
            if (target_user == NULL) { // Si le client n'est pas trouvé, informer le client
                response.payload = "[Server] user not found !";
                response.msg.pld_len = strlen(response.payload);
            } else { // Si le client est trouvé, récupérer ses informations
                response.payload = get_user_infos(target_user);
                response.msg.pld_len = strlen(response.payload);
            }

            send_wrapped_message(sockfd, &response); // Envoyer le message de réponse
            if (target_user != NULL) { // Libérer les informations du client si nécessaire
                free(response.payload);
            }
            break;

        case BROADCAST_SEND: // Broadcast
            if (w_msg->payload) { // Si le message contient un payload
                struct client_info *current = *client_list; // Pointeur vers la tête de la liste chainée
                while (current != NULL) { // Parcourir la liste chainée
                    if (current->sockfd != sockfd) { // Ne pas envoyer au client qui a envoyé le message
                        send_wrapped_message(current->sockfd, w_msg); // Envoyer le message au client
                    }
                    current = current->next;  // Passer au client suivant
                }
            }
            break;
        case UNICAST_SEND: // Unicast
            if (w_msg->payload) { // Si le message contient un payload
                struct client_info *target_user = get_client_by_nickname(w_msg->msg.infos,
                                                                         client_list); // Récupérer le client
                if (target_user == NULL) { // Si le client n'est pas trouvé, informer le client

                    w_msg->msg = create_server_message(UNICAST_SEND, "");
                    w_msg->payload = "[Server] user not found !";
                    w_msg->msg.pld_len = strlen(w_msg->payload);
                    send_wrapped_message(sockfd, w_msg);
                } else { // Si le client est trouvé, envoyer le message
                    send_wrapped_message(target_user->sockfd, w_msg);
                }
            }
            break;
        case MULTICAST_CREATE: // Création d'un canal

            if (create_channel(w_msg->msg.infos, channel_heads) != -1) { // Si le canal est disponible
                strcpy(w_msg->msg.infos, "good channel"); // Informer le client
            } else { // Si le canal est déjà utilisé
                strcpy(w_msg->msg.infos, "already used"); // Informer le client
            }
            send_wrapped_message(sockfd, w_msg);
            break;

        case MULTICAST_JOIN: // Rejoindre un canal
            if (strlen(w_msg->msg.infos) > 0) { // Si le message contient des informations

                struct channel_info *channel = get_channel_by_name(w_msg->msg.infos,
                                                                   channel_heads); // Récupérer le canal

                if (channel == NULL) {      // Le canal demandé n'existe pas, informer le client
                    handle_channel_not_found(w_msg, client, MULTICAST_JOIN);
                } else {  // Le canal demandé existe
                    if (channel->clients_head == NULL) { // La liste des clients est vide, initialiser la liste

                        channel->clients_head = malloc(
                                sizeof(struct client_info *)); // Allouer la mémoire pour la liste
                        *channel->clients_head = NULL; // Initialiser la liste à NULL


                    } else { // La liste des clients n'est pas vide

                        response.msg = create_server_message(MULTICAST_INFO,
                                                             channel->name); // Créer le message de notification
                        response.payload = "join"; // Mettre à jour le payload
                        strncpy_safe(response.msg.nick_sender, client->nickname, NICK_LEN); // Mettre à jour le nickname
                        response.msg.pld_len = strlen(response.payload); // Mettre à jour la taille du payload

                        send_to_channel(&response, client, channel); // Envoyer le message au canal


                    }
                    add_client_to_channel(client, channel);   // Ajouter le client à la liste des clients du canal


                    // Envoyer une réponse au client qui a rejoint
                    struct wrapped_message join_response;
                    memset(&join_response, 0, sizeof(join_response));
                    join_response.msg = create_server_message(MULTICAST_JOIN, channel->name);
                    join_response.payload = "[Server] you joined the channel !";
                    join_response.msg.pld_len = strlen(join_response.payload);
                    send_wrapped_message(sockfd, &join_response);

                }
            }
            break;

        case MULTICAST_QUIT: // Quitter un canal
            if (strlen(w_msg->msg.infos) > 0) { // Si le message contient des informations
                struct channel_info *channel = get_channel_by_name(w_msg->msg.infos,
                                                                   channel_heads); // Récupérer le canal
                if (channel == NULL) { // Le canal demandé n'existe pas, informer le client
                    handle_channel_not_found(w_msg, client, MULTICAST_QUIT);
                } else { // Le canal demandé existe
                    char channel_name[NICK_LEN]; // Chaine de caractère pour stocker le nom du canal
                    strncpy_safe(channel_name, channel->name, NICK_LEN - 1); // Copier le nom du canal


                    char last_user[] = "[Server] You were the last user in the channel, it has been destroyed."; // Dernier utilisateur
                    char left[] = "[Server] You left the channel."; // Utilisateur parti
                    char notin[] = "[Server] You were not in the channel."; // Utilisateur non trouvé


                    if (is_client_in_channel(client, channel) == 1) {  // Le client est dans le canal
                        struct client_info *current_client = *(channel->clients_head); // Pointeur vers la tête de la liste chainée
                        while (current_client != NULL) { // Parcourir la liste chainée
                            if (current_client->sockfd != client->sockfd) { // Ne pas envoyer au client qui quitte
                                struct wrapped_message notification_msg; // Créer le message de notification
                                notification_msg.msg = create_server_message(MULTICAST_INFO,
                                                                             channel_name); // Créer le message
                                notification_msg.payload = "quit"; // Mettre à jour le payload
                                strncpy_safe(notification_msg.msg.nick_sender, client->nickname,
                                             NICK_LEN); // Mettre à jour le nickname
                                notification_msg.msg.pld_len = strlen(
                                        notification_msg.payload); // Mettre à jour la taille du payload
                                send_wrapped_message(current_client->sockfd,
                                                     &notification_msg); // Envoyer le message au client
                            }
                            current_client = current_client->next; // Passer au client suivant
                        }

                        remove_client_from_channel(client,
                                                   channel); // Retirer le client de la liste des clients du canal

                        if (*channel->clients_head == NULL) { // Si la liste des clients est vide, supprimer le canal
                            remove_channel(channel, channel_heads); // Supprimer le canal

                            w_msg->payload = safe_malloc(strlen(last_user) + 1);
                            strcpy(w_msg->payload, last_user);
                        } else { // Si la liste des clients n'est pas vide, informer le client
                            w_msg->payload = safe_malloc(strlen(left) + 1);
                            strcpy(w_msg->payload, left);
                        }
                    } else {  // Le client n'est pas dans le canal, informer le client
                        w_msg->payload = safe_malloc(strlen(notin) + 1);
                        strcpy(w_msg->payload, notin);
                    }

                    // Envoyer une réponse au client qui a quitté
                    w_msg->msg = create_server_message(MULTICAST_QUIT, channel_name);
                    w_msg->msg.pld_len = strlen(w_msg->payload);
                    send_wrapped_message(sockfd, w_msg);
                }
            }
            break;

        case MULTICAST_SEND: // Envoyer un message à tous les clients d'un canal
            if (w_msg->payload) { // Si le message contient un payload
                struct channel_info *channel = get_channel_by_name(w_msg->msg.infos,
                                                                   channel_heads); // Récupérer le canal
                if (channel == NULL) { // Le canal demandé n'existe pas, informer le client
                    handle_channel_not_found(w_msg, client, MULTICAST_SEND);
                } else { // Le canal demandé existe
                    struct client_info **head = channel->clients_head; // Pointeur vers la tête de la liste chainée
                    struct client_info *current = *head; // Pointeur vers le client actuel
                    while (current != NULL) { // Parcourir la liste chainée
                        if (current->sockfd != sockfd) { // Ne pas envoyer au client qui a envoyé le message
                            send_wrapped_message(current->sockfd, w_msg); // Envoyer le message au client
                        }
                        current = current->next; // Passer au client suivant
                    }
                }
            }
            break;
        case MULTICAST_LIST: // Liste des canaux
            w_msg->msg = create_server_message(MULTICAST_LIST, ""); // Créer le message de réponse
            w_msg->payload = list_channels(channel_heads); // Récupérer la liste des canaux
            w_msg->msg.pld_len = strlen(w_msg->payload); // Mettre à jour la taille du payload
            send_wrapped_message(sockfd, w_msg); // Envoyer le message de réponse
            break;


            // dans ces 3 cas on retransmet le message au client cible
        case FILE_REQUEST:
        case FILE_ACCEPT:
        case FILE_REJECT: {
            struct client_info *target_user = get_client_by_nickname(w_msg->msg.infos,
                                                                     client_list); // Récupérer le client
            if (target_user == NULL) { // Si le client n'est pas trouvé, informer le client
                w_msg->msg = create_server_message(w_msg->msg.type, "");
                char *user_not_found = "[Server] user not found !";
                w_msg->payload = safe_malloc(strlen(user_not_found) + 1);
                strcpy(w_msg->payload, user_not_found);
                w_msg->msg.pld_len = strlen(w_msg->payload);
                send_wrapped_message(sockfd, w_msg);
            } else { // Si le client est trouvé, renvoyer le message

                send_wrapped_message(target_user->sockfd, w_msg);

            }

            break;

        }
        default: // Type de message non géré
            printf("Type de message non géré : %s\n", msg_type_str[w_msg->msg.type]);
            break;
    }


}


/*
 * Cette fonction permet de créer un socket et de le lier à une adresse.
 * Elle retourne le descripteur du socket.
 */
int handle_bind(char *server_port) {
    struct addrinfo hints, *result, *rp;
    int sfd;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if (getaddrinfo(NULL, server_port, &hints, &result) != 0) {
        perror("getaddrinfo()");
        exit(EXIT_FAILURE);
    }
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd == -1) {
            continue;
        }
        if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;
        }
        close(sfd);
    }
    if (rp == NULL) {
        fprintf(stderr, "Could not bind\n");
        exit(EXIT_FAILURE);
    }
    freeaddrinfo(result);
    return sfd;
}

/*
 * Fonction qui permet de libérer la mémoire
 */

struct client_info *client_list = NULL;
struct channel_info *channel_list = NULL;

void cleanup() {
    printf("[Server] closing server\n");

    // On libere tous les clients et la head
    struct client_info *current = client_list;
    while (current != NULL) {
        struct client_info *next = current->next;
        free(current);
        current = next;
    }
    free(client_list);

    // On libere tous les channels et la head
    struct channel_info *current_channel = channel_list;
    while (current_channel != NULL) {
        struct channel_info *next_channel = current_channel->next;
        free(current_channel);
        current_channel = next_channel;
    }
    free(channel_list);
}

int main(int argc, char *argv[]) {

    /*
     * Récupération du port du serveur.
     */
    if (argc != 2) {
        printf("Usage: %s <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    char *server_port = argv[1];


    int listening_fd;


    listening_fd = handle_bind(server_port);
    if (listen(listening_fd, SOMAXCONN) != 0) {
        perror("listen()\n");
        exit(EXIT_FAILURE);
    }


    int poll_fds_size = MAX_CLIENTS + 1;// +1 pour la socket d'écoute

    struct pollfd poll_fds[poll_fds_size];
    memset(poll_fds, 0, sizeof(poll_fds));

    poll_fds[0].fd = listening_fd; // On place la socket d'écoute en premier
    poll_fds[0].events = POLLIN; // On veut être notifié lorsqu'un client se connecte
    poll_fds[0].revents = 0; // On remet à 0 pour éviter les mauvaises surprises

    int client_count = 1; // Commence à 1 car la socket d'écoute est déjà enregistrée

    while (1) { // Boucle infinie

        if (poll(poll_fds, poll_fds_size, -1) == -1) {
            perror("Poll");
            exit(EXIT_FAILURE);
        }

        // Si il y a une nouvelle connexion
        if (poll_fds[0].revents & POLLIN) {
            if (client_count >= MAX_CLIENTS + 1) { // Si le nombre maximum de connexion est atteint
                printf("Nombre maximum de connexion atteint.\n");
                continue; // On continue pour ne pas crash le serveur. Il faudrait ajouter un système pour traiter l'erreur
            }

            struct sockaddr_in client_address;
            socklen_t client_address_len = sizeof(client_address);
            int new_client_fd = accept(listening_fd, (struct sockaddr *) &client_address,
                                       &client_address_len); // Accepter la connexion entrante

            if (new_client_fd < 0) { // Si le descripteur de fichier est inférieur à 0, il y a eu une erreur
                perror("accept");
                continue;
            }

            printf("Nouvelle connection : %s:%d\n", inet_ntoa(client_address.sin_addr),
                   ntohs(client_address.sin_port)); // Afficher l'adresse IP et le port du client
            add_client(new_client_fd, client_address, &client_list); // Ajouter le client à la liste chainée
            poll_fds[client_count].fd = new_client_fd; // Ajouter le client au tableau de poll
            poll_fds[client_count].events = POLLIN; // On veut être notifié lorsqu'un client envoie un message
            poll_fds[client_count].revents = 0; // On remet à 0 pour éviter les mauvaises surprises

            poll_fds[0].revents = 0; // On remet à 0 pour éviter les mauvaises surprises

            client_count++; // Incrémenter le nombre de clients connectés

        }


        if (poll_fds[0].revents & POLLERR) {    // S'il y a une erreur sur le Poll

            perror("Poll");
            exit(EXIT_FAILURE);
        }

        // Pour chaque client connecté
        for (int i = 1; i < client_count; i++) {
            if (poll_fds[i].revents & POLLIN) { // On regarde s'il y a des données à lire

                int client_fd = poll_fds[i].fd; // Récupérer le descripteur de fichier du client

                struct wrapped_message *w_msg = receive_msg(client_fd, &client_list); // Récupérer le message

                if (w_msg == NULL) { // Si le message est nul, il y a eu une erreur
                    continue; // On continue pour ne pas crash le serveur. Il faudrait ajouter un système pour traiter l'erreur
                }

                if (w_msg->payload && (strcmp(w_msg->payload, "/quit\n") ==
                                       0)) { // Si le message contient /quit, le client veut se déconnecter
                    printf("Déconnexion de : %s\n",
                           get_client(client_fd, &client_list)->nickname); // Afficher le nickname du client
                    struct channel_info *channel = get_channel_by_name(w_msg->msg.infos,
                                                                       &channel_list); // Récupérer le canal
                    if (channel != NULL) { // Si le canal est trouvé
                        remove_client_from_channel(get_client(client_fd, &client_list),
                                                   channel); // Retirer le client du canal
                    }
                    remove_client(client_fd, &client_list); // Retirer le client de la liste chainée
                    close(client_fd); // Fermer le socket
                    free(w_msg->payload); // Libérer le payload
                    free(w_msg);  // Libérer la structure wrapped_message
                    continue;
                }

                handle_message(w_msg, &client_list, poll_fds[i].fd, &channel_list); // Gérer le message

                if (w_msg->payload) { // Libérer le payload
                    free(w_msg->payload);
                }
                free(w_msg); // Libérer la structure wrapped_message

                poll_fds[i].revents = 0; // On remet à 0 pour éviter les mauvaises surprises

            }
        }


    }
    cleanup(); // Libérer la mémoire
    return EXIT_SUCCESS;
}

