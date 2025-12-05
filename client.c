#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdint.h>  

#define MAX_BUF 1024
#define SOCKET_PATH "/tmp/server_socket"

// Functie pentru a primi raspunsul cu prefix de lungime
char* receive_response(int fd) {
    uint32_t length;
    if (read(fd, &length, sizeof(length)) != sizeof(length)) {
        return NULL;
    }
    
    char* response = malloc(length + 1);
    if (!response) {
        perror("Memory allocation failed");
        return NULL;
    }
    
    ssize_t bytes_read = read(fd, response, length);
    if (bytes_read < 0) {
        free(response);
        return NULL;
    }
    
    response[bytes_read] = '\0';
    return response;
}

int main() {
    int sock_fd;
    struct sockaddr_un server_addr;
    char buffer[MAX_BUF];
    
    if ((sock_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    // Setam adresa serverului
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, SOCKET_PATH, sizeof(server_addr.sun_path) - 1);
    
    if (connect(sock_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }
    
    printf("Connected to server\n");
    printf("Available commands:\n");
    printf("  login : username\n");
    printf("  get-logged-users\n");
    printf("  get-proc-info : pid\n");
    printf("  logout\n");
    printf("  quit\n");
    
    while (1) {
        printf("> ");
        if (!fgets(buffer, MAX_BUF, stdin)) {
            break;
        }
        
        buffer[strcspn(buffer, "\n")] = 0;
        
        if (strlen(buffer) == 0) {
            continue;
        }
        
        write(sock_fd, buffer, strlen(buffer));
        
        if (strcmp(buffer, "quit") == 0) {
            char *response = receive_response(sock_fd);
            if (response) {
                printf("%s", response);
                free(response);
            }
            break;
        }
        
        char *response = receive_response(sock_fd);
        if (response) {
            printf("%s", response);
            free(response);
        } else {
            printf("Error: Failed to receive response from server\n");
            break;
        }
    }
    
    close(sock_fd);
    return 0;
}