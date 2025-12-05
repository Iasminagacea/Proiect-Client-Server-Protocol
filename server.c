#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <utmp.h>
#include <signal.h>
#include <sys/wait.h>
#include <stdint.h>  

#define MAX_BUF 1024
#define SOCKET_PATH "/tmp/server_socket"
#define FIFO_PATH "/tmp/server_fifo"

int authenticated = 0;
char fifo_path[256];

void send_response(int fd, const char* response) {
    uint32_t length = strlen(response);
    write(fd, &length, sizeof(length)); 
    write(fd, response, length);       
}

void handle_login(const char *username, int pipe_fd) {
    FILE *file = fopen("users.txt", "r");
    char buffer[MAX_BUF] = "";
    int found = 0;
    
    if (!file) {
        strcpy(buffer, "Error: Cannot open users file\n");
    } else {
        char line[256];
        while (fgets(line, sizeof(line), file)) {
            if (line[strlen(line) - 1] == '\n') 
                line[strlen(line) - 1] = '\0';   //Eliminam newline-ul
            
            if (strcmp(line, username) == 0) {
                found = 1;
                sprintf(buffer, "Login successful for user: %s\n", username);
                break;
            }
        }
        fclose(file);
        
        if (!found) {
            sprintf(buffer, "User '%s' not found\n", username);
        }
    }
    
    write(pipe_fd, buffer, strlen(buffer) + 1); 
}

void handle_get_logged_users(int pipe_fd) {
    struct utmp *utmp_entry;
    char buffer[MAX_BUF] = "";
    
    if (!authenticated) {
        strcpy(buffer, "Not authenticated\n");
    } else {
        setutent();
        
        while ((utmp_entry = getutent()) != NULL) {
            if (utmp_entry->ut_type == USER_PROCESS) {
                char temp[256];
                snprintf(temp, sizeof(temp), "User: %s, Host: %s, Time: %ld\n", 
                        utmp_entry->ut_user, utmp_entry->ut_host, utmp_entry->ut_time);
                strcat(buffer, temp);
            }
        }
        
        endutent();
        if (strlen(buffer) == 0) {
            strcpy(buffer, "No logged users found\n");
        }
    }
    
    write(pipe_fd, buffer, strlen(buffer) + 1);
}

void handle_proc_info(const char *pid_str, int pipe_fd) {
    char buffer[MAX_BUF] = "";
    
    if (!authenticated) {
        strcpy(buffer, "Not authenticated\n");
    } else {
        char path[256];
        snprintf(path, sizeof(path), "/proc/%s/status", pid_str);
        
        FILE *file = fopen(path, "r");
        if (!file) {
            snprintf(buffer, MAX_BUF, "Error: Cannot open process info for PID %s\n", pid_str);
        } else {
            char name[256] = "Unknown";
            char state[256] = "Unknown";
            int ppid = -1;
            int uid = -1;
            long vmsize = -1;
            
            char line[256];
            while (fgets(line, sizeof(line), file)) {
                if (strncmp(line, "Name:", 5) == 0)
                    sscanf(line, "Name: %s", name);
                else if (strncmp(line, "State:", 6) == 0)
                    sscanf(line, "State: %s", state);
                else if (strncmp(line, "PPid:", 5) == 0)
                    sscanf(line, "PPid: %d", &ppid);
                else if (strncmp(line, "Uid:", 4) == 0)
                    sscanf(line, "Uid: %d", &uid);
                else if (strncmp(line, "VmSize:", 7) == 0)
                    sscanf(line, "VmSize: %ld", &vmsize);
            }
            
            fclose(file);
            
            snprintf(buffer, MAX_BUF, 
                    "Process info for PID %s:\n"
                    "Name: %s\n"
                    "State: %s\n"
                    "PPID: %d\n"
                    "UID: %d\n"
                    "VmSize: %ld\n",
                    pid_str, name, state, ppid, uid, vmsize);
        }
    }
    
    write(pipe_fd, buffer, strlen(buffer) + 1);
}

void cleanup() {
    unlink(SOCKET_PATH);
    unlink(FIFO_PATH);
}

int main() {
    int server_fd, client_fd;
    struct sockaddr_un server_addr, client_addr;
    socklen_t client_len;
    char buffer[MAX_BUF];

    signal(SIGINT, cleanup);
    atexit(cleanup);
    
    if ((server_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, SOCKET_PATH, sizeof(server_addr.sun_path) - 1);
    
    unlink(SOCKET_PATH);
    
    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }
    
    if (listen(server_fd, 5) == -1) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }
    
    mkfifo(FIFO_PATH, 0666);
    
    printf("Server started. Waiting for connections...\n");
    
    while (1) {
        client_len = sizeof(client_addr);
        if ((client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len)) == -1) {
            perror("Accept failed");
            continue;
        }
        
        printf("Client connected\n");
        authenticated = 0; 
        
        while (1) {
            int n = read(client_fd, buffer, MAX_BUF);
            if (n <= 0) {
                printf("Client disconnected\n");
                break;
            }
            
            buffer[n] = '\0';
            printf("Received: %s\n", buffer);
            
            if (strncmp(buffer, "login : ", 8) == 0) {
                char *username = buffer + 8;
                
                int pipefd[2];
                if (pipe(pipefd) == -1) {
                    perror("Pipe creation failed");
                    send_response(client_fd, "Internal server error\n");
                    continue;
                }
                
                pid_t pid = fork();
                if (pid == -1) {
                    perror("Fork failed");
                    send_response(client_fd, "Internal server error\n");
                    continue;
                }
                
                if (pid == 0) {
                    close(pipefd[0]); 
                    handle_login(username, pipefd[1]);
                    close(pipefd[1]);
                    exit(0);
                } else {
                    close(pipefd[1]);
                    
                    char resp[MAX_BUF] = {0};
                    read(pipefd[0], resp, MAX_BUF);
                    close(pipefd[0]);
                    
                    if (strstr(resp, "Login successful") != NULL) {
                        authenticated = 1;
                    }
                    
                    send_response(client_fd, resp);
                    
                    waitpid(pid, NULL, 0);
                }
            }
            else if (strcmp(buffer, "get-logged-users") == 0) {
                int sockets[2];
                if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == -1) {
                    perror("Socketpair creation failed");
                    send_response(client_fd, "Internal server error\n");
                    continue;
                }
                
                pid_t pid = fork();
                if (pid == -1) {
                    perror("Fork failed");
                    close(sockets[0]);
                    close(sockets[1]);
                    send_response(client_fd, "Internal server error\n");
                    continue;
                }
                
                if (pid == 0) {
                    close(sockets[0]);  
                    handle_get_logged_users(sockets[1]);
                    close(sockets[1]);
                    exit(0);
                } else {
                    close(sockets[1]); 
                    
                    char resp[MAX_BUF] = {0};
                    read(sockets[0], resp, MAX_BUF);
                    close(sockets[0]);
                    
                    send_response(client_fd, resp);
                    
                    waitpid(pid, NULL, 0);
                }
            }
            else if (strncmp(buffer, "get-proc-info : ", 16) == 0) {
                char *pid_str = buffer + 16;
                
                sprintf(fifo_path, "%s_%d", FIFO_PATH, getpid());
                mkfifo(fifo_path, 0666);
                
                pid_t pid = fork();
                if (pid == -1) {
                    perror("Fork failed");
                    send_response(client_fd, "Internal server error\n");
                    unlink(fifo_path);
                    continue;
                }
                
                if (pid == 0) {
                    int fifo_fd = open(fifo_path, O_WRONLY);
                    if (fifo_fd == -1) {
                        perror("Failed to open FIFO");
                        exit(1);
                    }
                    
                    handle_proc_info(pid_str, fifo_fd);
                    close(fifo_fd);
                    exit(0);
                } else {
                    int fifo_fd = open(fifo_path, O_RDONLY);
                    if (fifo_fd == -1) {
                        perror("Failed to open FIFO");
                        send_response(client_fd, "Internal server error\n");
                        unlink(fifo_path);
                        continue;
                    }
                    
                    char resp[MAX_BUF] = {0};
                    read(fifo_fd, resp, MAX_BUF);
                    close(fifo_fd);
                    unlink(fifo_path);
                    
                    send_response(client_fd, resp);
                    
                    waitpid(pid, NULL, 0);
                }
            }
            else if (strcmp(buffer, "logout") == 0) {
                if (!authenticated) {
                    send_response(client_fd, "Error: You are not logged in\n");
                } else {
                    authenticated = 0;
                    send_response(client_fd, "Logged out successfully\n");
                }
            }
            else if (strcmp(buffer, "quit") == 0) {
                send_response(client_fd, "Goodbye!\n");
                break;
            }
            else {
                send_response(client_fd, "Unknown command\n");
            }
        }
        
        close(client_fd);
    }
    
    close(server_fd);
    unlink(SOCKET_PATH);
    unlink(FIFO_PATH);
    
    return 0;
}