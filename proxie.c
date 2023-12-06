#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pthread.h>
#include <errno.h>
#include <openssl/md5.h>
#include <sys/time.h>

pthread_t tid;

/* Mutex for thread syncronisation */
pthread_mutex_t dns_lock;   
pthread_mutex_t cache_lock;

/* Global Defines */
#define MAXLINE 8192 /* max text line length */
#define MAXBUF 8192  /* max I/O buffer size */
#define LISTENQ 1024 /* second argument to listen() */


char cacheDNSBuffer[MAXLINE];
int timeout;
int timeout_flag = 1;  
char globalhttp[20] = "HTTP/1.1";

int open_listenfd(int port);
void *thread(void *vargp);
void throw_error(int connfd, char *msg);
int check_if_blacklisted(char *hostname, char *ip);
int check_dns_cache(char *hostname, struct in_addr *cache_addr);
int add_ip_to_cache(char *hostname, char *ip);
void md5_str(char *str, char *md5buf);
int check_cache_md5(char *fname);
void send_file_from_cache(int connfd, char *fname);
void echo(int connfd);
void generate_prefetch_requests(char *host_name);
void prefetch_link(char *link);

int main(int argc, char **argv)
{
  /* Checking use of command line arguments */
  if (argc == 2)
  {
    /* If no timeout provided keep default timeout value of 0 Sec */
    timeout = 0;
    timeout_flag = 0;
  } else if (argc == 3)
  {
    /* Timeout provided from command line argument */
    timeout = atoi(argv[2]);
  } else
  {
    printf("usage: %s <port>\nor: %s <port> <timeout>\n", argv[0], argv[0]);
    exit(0);
  }

  int listen_fd, *conn_fdp, port;

  int client_len = sizeof(struct sockaddr_in);
  struct sockaddr_in client_addr;

  memset(cacheDNSBuffer, 0, sizeof(cacheDNSBuffer));

  /* Print time out and port number */
  port = atoi(argv[1]);
  printf("Port Selected \t = %d \n", port);
  printf("Timeout Value \t = %d Sec \n", timeout);
  

  pthread_mutex_init(&dns_lock, NULL);
  pthread_mutex_init(&cache_lock, NULL);

  listen_fd = open_listenfd(port);

  /* Continuesly check for connection request */
  while (1)
  {
    conn_fdp = malloc(sizeof(int));

    /* Accept a connection on out listenning socket and create a new connected socket */
    *conn_fdp = accept(listen_fd, (struct sockaddr *)&client_addr, &client_len);

    /* Pass the connected socket after connection is established into a seperate thread function */
    pthread_create(&tid, NULL, thread, conn_fdp);
  }
}
/*
 * Function opens a listening socket
 * and returns the ID of that socket
 * Returns -1 in case of failure
 */
int open_listenfd(int port)
{
  int listen_fd, optval = 1;
  struct sockaddr_in server_addr;

  /* Creating an endpoint for communication using socket(2) */
  if ((listen_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    return -1;

  /* Set socket option to eliminate error "Address already in use" from bind. */
  if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR,
                 (const void *)&optval, sizeof(int)) < 0)
    return -1;

  /* Building up server address configurations */
  bzero((char *)&server_addr, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  server_addr.sin_port = htons((unsigned short)port);

  /* Binding socket to the server address */
  if (bind(listen_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    return -1;

  /* Make socket ready to accept incoming connection request using listen(3) */
  if (listen(listen_fd, LISTENQ) < 0)
    return -1;
  return listen_fd;
}

/* Thread routine */
void *thread(void *vargp)
{
  int connfd = *((int *)vargp);
  pthread_detach(pthread_self());
  free(vargp);
  printf("\nConnfd Value: %d\n", connfd);
  echo(connfd);
  close(connfd);
  return NULL;
}

void *handle_prefetch_threads(void *vargp)
{
    char *filename;
    filename = (char *)vargp;
    generate_prefetch_requests(filename);
    pthread_detach(pthread_self());
    free(vargp);
    return NULL;
}

void *handle_prefetch_requests(void *vargp)
{
    char *link;
    link = (char *)vargp;
    prefetch_link(link);
    pthread_detach(pthread_self());
    free(vargp);
    return NULL;
}

void prefetch_link(char *link)
{   
  int sock_fd;
  char *hosname = strtok(link, ":");
  char *file = strtok(NULL, "\0");
  
  //Implement cache processing
  /* Store MD5 Input for example netsys.cs.colorado.edu/index.html*/
  char MD5_inp[strlen(hosname) + strlen(file) + 2]; /* Two extra bytes for "/" and Null terminator "\0"*/
  strcpy(MD5_inp, hosname);
  strcat(MD5_inp, "/");
  strcat(MD5_inp, file);

  /* Store MD5 Output */
  /* 16 Byte Hex Value + 2 characters for int + Null terminator i.e 33 Bytes in total */
  char MD5_out[33];

  memset(MD5_out, 0, sizeof(MD5_out));

  md5_str(MD5_inp, MD5_out);

  /* Store Cache file as example "cache/8ef7ececfe8528bffb1d8ae1f639ce16" */
  char cache_buf[strlen("cache/") + strlen(MD5_out)]; /* Buffer file directory with relative path */
  strcpy(cache_buf, "cache/");
  strcat(cache_buf, MD5_out);
  
  char req_directory[strlen("cache/") + 1];
  strcpy(req_directory, "cache/");

  if (check_cache_md5(MD5_out))
  { 
    return;
  }
  sock_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (sock_fd < 0)
  {
    printf("Faild to open socket");
  }
  struct sockaddr_in server_addr;
  bzero((char *)&server_addr, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(80);
  struct hostent *server;
  struct in_addr cache_addr;
  int server_addr_cache = check_dns_cache(hosname, &cache_addr);
  if (server_addr_cache == -1)
  {
    printf("Host %s not in DNS cache\n", hosname);
    server = gethostbyname(hosname);
    if (server == NULL)
    {
      printf("Failed to resolve host %s, responding with 404 error\n", hosname);
      //throw_error(connfd, "404 Not Found");
      return;
    }
    bcopy((char *)server->h_addr, (char *)&server_addr.sin_addr.s_addr, server->h_length);
  }
  else
  { // in cache
    server_addr.sin_addr.s_addr = cache_addr.s_addr;
  }
  char IP_Addr_buf[20];
  if (inet_ntop(AF_INET, (char *)&server_addr.sin_addr.s_addr, IP_Addr_buf, (socklen_t)20) == NULL)
  {
    printf("Failed to convert hostname to IP\n");
    return;
  }
  
  /* If the current hostname and IP is not in cache create a new entry for it */
  if (server_addr_cache == -1)
  {
    /* Load IP of hostname into ./cache */
    int success = add_ip_to_cache(hosname, IP_Addr_buf);
    /* No more space in ./cache cant create entry */
    if (success == -1)
    {
      printf("Cache full, cannot add entry %s:%s\n", hosname, IP_Addr_buf);
    }
  }
  // printf("Host: %s, IP: %s\n", http_hostname, IP_Addr_buf);
  int server_len = sizeof(server_addr);
  int conn_size;
  conn_size = connect(sock_fd, (struct sockaddr *)&server_addr, server_len);
  if (conn_size < 0)
  {
    printf("Failed to connect\n");
    return;
  }
  
  char buffub[MAXLINE];
  memset(buffub, 0, MAXLINE);
  sprintf(buffub, "GET /%s %s\r\nHost: %s\r\n\r\n", file, globalhttp, hosname);
  conn_size = write(sock_fd, buffub, sizeof(buffub));
  if (conn_size < 0)
  {
    printf("Failed to sendto\n");
    return;
  }
  
  int total_size = 0;
  memset(buffub, 0, sizeof(buffub));
  FILE *filep;
  filep = fopen(cache_buf, "wb");
  pthread_mutex_lock(&cache_lock);
  while ((conn_size = read(sock_fd, buffub, sizeof(buffub))) > 0)
  {
    if (conn_size < 0)
    {
      printf("Failed to recvfrom\n");
      return;
    }
    fwrite(buffub, 1, conn_size, filep);
    memset(buffub, 0, sizeof(buffub));
  }
  pthread_mutex_unlock(&cache_lock);
  printf("\nCached this file in prefetch - %s -> %s", file, MD5_out);
  fclose(filep);
  return;
}

// Parses html and creates new prefetch threads.
void generate_prefetch_requests(char *host_name_plus_cachebuf)
{   
    // host_name = cache/md5sum
    printf("Generating prefetch for: %s\n", host_name_plus_cachebuf);
    char *filename;
    // strtok_r(host_name, ":", &filename);
    char *host_name_og = strtok(host_name_plus_cachebuf, ":");
    char *host_name = strtok(NULL, "\0");
    FILE *f;
    char fileBuf[MAXBUF];
    // host_name index.html -> cache/md5.sum
    f = fopen(host_name,"r");
    if(!f)
    {
        printf("Link linkPreFetchThreadCreator Failed!\n");
        return;
    }

    // Parse the HTML to find prefetch links.
    char *token;
    char website_name[200];
    pthread_t tid;
    char *fn;
    while(fgets(fileBuf,MAXBUF,f) != NULL)
    {
        if(strstr(fileBuf,"href") != NULL)
        {
            if(strstr(fileBuf,"<a") || strstr(fileBuf,"</a>"))
            {
                if(strstr(fileBuf,"http") == NULL)
                {
    
                    token = strstr(fileBuf,"href=" )+strlen("href=")+1;
                    token = strtok(token,"\"");
                    if(strcmp(token,"#") != 0)
                    {
                        sprintf(website_name,"%s:%s",host_name_og, token);
                        fn = (char *)malloc(strlen(website_name)+1*sizeof(char));
                        strcpy(fn,website_name);
                        pthread_create(&tid, NULL, handle_prefetch_requests, fn);
                    }
                }
                else 
                {   
                    if(strstr(fileBuf,"https") == NULL)
                    {
                        
                        token = strstr(fileBuf,"//")+strlen("//");
                        token = strtok(token,"\"");
                        sprintf(website_name,"%s:%s",host_name_og, token);
                        fn = (char *)malloc(strlen(website_name)+1*sizeof(char));
                        strcpy(fn,website_name);
                        pthread_create(&tid, NULL, handle_prefetch_requests, fn);
                    }
                }
            }
        }
    }
    fclose(f);
}

void echo(int connfd)
{
  size_t n;
  char buf[MAXLINE];

  struct hostent *server;
  int sock_fd;
  int conn_size;
  int portno = 80;
  int is_html = 0;
  /* read from connected socket and load data into buffer */
  n = read(connfd, buf, MAXLINE);
  printf("\n%s\n", buf);
  printf("\nPROXY SERVER RECEIVED A REQUEST\n\n");

  /* Parsing HTTP request from client */
  char *http_request = strtok(buf, " "); // GET or POST
  char *http_hostname = strtok(NULL, " ");
  char *http_version = strtok(NULL, "\r"); // HTTP/1.1 or HTTP/1.0
  char file_name[MAXLINE];

  printf("Method\t: %s\nHostname\t: %s\nVersion\t\t: %s\n\n", http_request, http_hostname, http_version);

  /* Error Detection */
  if (http_hostname == NULL || http_version == NULL)
  {
    printf("Hostname Version not provided or maybe NULL\n");
    throw_error(connfd, "500 Internal Server Error");
    return;
  }

  if (strlen(http_hostname) == 0)
  {
    printf("No host requested, responding with error\n");
    throw_error(connfd, "500 Internal Server Error");
    return;
  }

  if (!strcmp(http_version, "HTTP/1.1") || !strcmp(http_version, "HTTP/1.0"))
  {
  }
  else
  {
    printf("Invalid HTTP version: %s\n", http_version);
    throw_error(connfd, "500 Internal Server Error");
    return;
  }

  if (!strcmp(http_request, "GET"))
  {
  }
  else
  {
    printf("Invalid request method: %s\n", http_request);
    throw_error(connfd, "400 Bad Request");
    return;
  }

  /* Strip HTTP:// from hostname to eliminate the error from gethostbyname */
  char *double_Slash = strstr(http_hostname, "//");
  if (double_Slash != NULL)
  {
    http_hostname = double_Slash + 2;
  }

  /* seperate host name and file name from HTTP Request */
  char *Slash = strchr(http_hostname, '/');
  if (Slash == NULL || *(Slash + 1) == '\0')
  { // If no file is explicitly requested, get default
    printf("Default page requested.............................................................\n\n");
    strcpy(file_name, "index.html");
  }

  else
  { // Otherwise, copy requested filename to buffer
    strcpy(file_name, Slash + 1);
  }

  printf("Host\t\t: %s\nFile\t\t: %s\n", http_hostname, file_name);

  // Set string to end after hostname so the file is not part of DNS query
  if (Slash != NULL)
  {
    *Slash = '\0';
  }

  /* Store MD5 Input for example netsys.cs.colorado.edu/index.html*/
  char MD5_inp[strlen(http_hostname) + strlen(file_name) + 2]; /* Two extra bytes for "/" and Null terminator "\0"*/
  strcpy(MD5_inp, http_hostname);
  strcat(MD5_inp, "/");
  strcat(MD5_inp, file_name);

  /* Store MD5 Output */
  /* 16 Byte Hex Value + 2 characters for int + Null terminator i.e 33 Bytes in total */
  char MD5_out[33];

  memset(MD5_out, 0, sizeof(MD5_out));

  md5_str(MD5_inp, MD5_out);

  /* Store Cache file as example "cache/8ef7ececfe8528bffb1d8ae1f639ce16" */
  char cache_buf[strlen("cache/") + strlen(MD5_out)]; /* Buffer file directory with relative path */
  strcpy(cache_buf, "cache/");
  strcat(cache_buf, MD5_out);
  
  char req_directory[strlen("cache/") + 1];
  strcpy(req_directory, "cache/");

  // Implement Link Prefetch
  
  // Keep the below thing in loop

  if (check_cache_md5(MD5_out))
  {
    printf("Sending file back to client from cache: \t%s\n", cache_buf);
    send_file_from_cache(connfd, cache_buf);
    return;
  }

  sock_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (sock_fd < 0)
  {
    printf("Faild to open socket");
  }

  struct sockaddr_in server_addr;

  bzero((char *)&server_addr, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(portno);

  struct in_addr cache_addr;
  int server_addr_cache = check_dns_cache(http_hostname, &cache_addr);
  if (server_addr_cache == -1)
  {
    printf("Host %s not in DNS cache\n", http_hostname);
    server = gethostbyname(http_hostname);
    if (server == NULL)
    {
      printf("Failed to resolve host %s, responding with 404 error\n", http_hostname);
      throw_error(connfd, "404 Not Found");
      return;
    }
    bcopy((char *)server->h_addr,
          (char *)&server_addr.sin_addr.s_addr, server->h_length);
  }
  else
  { // in cache
    server_addr.sin_addr.s_addr = cache_addr.s_addr;
  }

  /* Converting hostname to its IP using inet_ntop() */
  char IP_Addr_buf[20];
  if (inet_ntop(AF_INET, (char *)&server_addr.sin_addr.s_addr, IP_Addr_buf, (socklen_t)20) == NULL)
  {
    printf("Failed to convert hostname to IP\n");
    return;
  }

  /* If the current hostname and IP is not in cache create a new entry for it */
  if (server_addr_cache == -1)
  {
    /* Load IP of hostname into ./cache */
    int success = add_ip_to_cache(http_hostname, IP_Addr_buf);
    /* No more space in ./cache cant create entry */
    if (success == -1)
    {
      printf("Cache full, cannot add entry %s:%s\n", http_hostname, IP_Addr_buf);
    }
  }
  printf("Host: %s, IP: %s\n", http_hostname, IP_Addr_buf);
  char backup_hostname[100];
  strcpy(backup_hostname, http_hostname);
 
  printf("\nDebugg Blacklist:  ", backup_hostname);
  /* Checking for the Blacklist for given IP and hostname */
  printf("\nChecking Blacklist\n");
  if (check_if_blacklisted(backup_hostname, IP_Addr_buf))
  {
    /* HTTP 403 Forbidden Error thrown */
    throw_error(connfd, "403 Forbidden");
    printf("\nForbidden Host\n");
    return;
  }

  int server_len = sizeof(server_addr);

  conn_size = connect(sock_fd, (struct sockaddr *)&server_addr, server_len);
  if (conn_size < 0)
  {
    printf("Failed to connect\n");
    return;
  }

  memset(buf, 0, MAXLINE);
  sprintf(buf, "GET /%s %s\r\nHost: %s\r\n\r\n", file_name, http_version, http_hostname);

  conn_size = write(sock_fd, buf, sizeof(buf));
  if (conn_size < 0)
  {
    printf("Failed to sendto\n");
    return;
  }

  int total_size = 0;
  memset(buf, 0, sizeof(buf));

  FILE *file;
  file = fopen(cache_buf, "wb");
  pthread_mutex_lock(&cache_lock);
  while ((conn_size = read(sock_fd, buf, sizeof(buf))) > 0)
  {
    if (conn_size < 0)
    {
      printf("Failed to recvfrom\n");
      return;
    }

    total_size += conn_size;

    write(connfd, buf, conn_size);
    fwrite(buf, 1, conn_size, file);
    memset(buf, 0, sizeof(buf));
  }
  pthread_mutex_unlock(&cache_lock);
  fclose(file);
  if(strstr(file_name,".html") != NULL)
  {
    is_html = 1;
  }
  if(is_html == 1)
  {
    // cache_buf
    // char websiteFileName[200];
    // sprintf(websiteFileName,"%s:%s",http_hostname,file_name);
    pthread_t tid;
    char websiteFileName[200];
    sprintf(websiteFileName,"%s:%s",backup_hostname,cache_buf);
    char *fn;
    fn = (char *)malloc(strlen(websiteFileName)+1*sizeof(char));
    strcpy(fn, websiteFileName);
    printf("Starting prefetch thread for: %s%s\n", backup_hostname, req_directory);
    pthread_create(&tid, NULL, handle_prefetch_threads, fn);
    
  }
  if (conn_size == -1)
  {
    //printf("Failed to read - errno:%d\n", errno);
    return;
  }
  
}

int check_cache_md5(char *fname)
{
  struct stat fileStat;
  DIR *dir = opendir("./cache");

  // sizeof("cache") includes null terminator, but it will be replace with '/'
  char buf[strlen("cache/") + strlen(fname)];
  memset(buf, 0, sizeof(buf));
  strcpy(buf, "cache/");
  strcat(buf, fname);
  if (dir)
  {
    closedir(dir);
    if (stat(buf, &fileStat) != 0)
    {
      printf("File not cached, Creating new...\n");
      return 0;
    }
    printf("\nChecking cache timeout...\n");
    char buffer[80];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", localtime(&(fileStat.st_mtime)));
    printf("'Cached File' Creation Time: %s\n", buffer);

    time_t file_modify = fileStat.st_mtime;
    time_t current_time = time(NULL);
    double diff = difftime(current_time, file_modify);
    if (diff > timeout && timeout_flag == 1)
    {
      if (access(buf, W_OK) == 0)
      {
        if (remove(buf) == 0)
        {
          printf("md5 cache expired, creating new cache\n");
          return 0;
        }
        else
        {
          printf("Error clearing cache %s\n", buf);
          return 1;
        }
      }
      else
      {
        printf("Error in cache access\n");
        return 1;
      }
    }
    if (timeout == 0)
    {
      printf("Timeout feature: Disabled\n");
      return 1;
    }
    // File is valid until (current - file_creation) time > timeout
    printf("Caching Requested File from Proxy Server\n");
    return 1;
  }

  if (dir)
  {
    closedir(dir);
    if (stat(buf, &fileStat) != 0)
    {
      printf("File not in cache\n");
      return 0;
    }
    printf("File located in cache folder, Figuring out for timeout...\n");
    if (timeout == 0)
    {
      printf("Timeout value not given\n");
      return 1;
    }
    /* Checking timeout expired or not  */
    time_t time_file_modify = fileStat.st_mtime;
    time_t time_current = time(NULL);
    double time_diff = difftime(time_current, time_file_modify);
    if (time_diff > timeout)
    {
      printf("Timeout occurred: file has been modified %.2f seconds ago, Given timeout is %d\n", time_diff, timeout);
      return 0;
    }
    printf("File is cachable for %d more seconds since timeout is yet to elapse\n", timeout - (int)time_diff);
    return 1;
  }
  /* If folder ./cache doesnt exits create one */
  else if (errno == ENOENT)
  {
    printf("Cache folder not found, creating...\n");
    mkdir("cache", 0777);
    printf("Created directory ./cache \n");
    if (dir)
    {
      closedir(dir);
    }
    return 0;
  }
  else
  {
    printf("Failed to open cache folder\n");
    return 0;
  }
}


void send_file_from_cache(int connfd, char *fname)
{
  FILE *file = fopen(fname, "rb");
  if (!file)
  {
    printf("Fail to open file %s\n", fname);
    return;
  }
  fseek(file, 0L, SEEK_END);
  int fsize = ftell(file);
  rewind(file);
  char *file_buf = malloc(fsize);
  if (!file_buf)
  {
    printf("Error allocating memory for file buffer\n");
    fclose(file);
    return;
  }
  // char file_buf[fsize];
  fread(file_buf, 1, fsize, file);
  write(connfd, file_buf, fsize);
} /* end send_file_from_cache*/


void throw_error(int connfd, char *msg)
{
  char error_msg[MAXLINE];
  sprintf(error_msg, "HTTP/1.1 %s\r\nContent-Type:text/plain\r\nContent-Length:0\r\n\r\n", msg);
  write(connfd, error_msg, strlen(error_msg));
}

/* Function checks if the given IP of
 * hostname is blacklisted as per blacklist.txt
 */
int check_if_blacklisted(char *hostname, char *ip)
{
  FILE *file;
  char blacklist_line[100];
  char *newline;

  if (access("blacklist", F_OK) == -1)
  {
    printf("No blacklist named blacklist.txt found\n");
    return 0;
  }
  file = fopen("blacklist", "r");
  while (fgets(blacklist_line, sizeof(blacklist_line), file))
  {
    newline = strchr(blacklist_line, '\n');
    if (newline != NULL)
    {
      *newline = '\0';
    }
    /* Checking in blacklist */
    if (strstr(blacklist_line, hostname) || strstr(blacklist_line, ip))
    {
      printf("Blacklist hostname found: %s\n", blacklist_line);
      return 1;
    }
  }
  fclose(file);
  printf("Hostname not found in blacklist\n");
  return 0;
}

int check_dns_cache(char *hostname, struct in_addr *cache_addr)
{
  printf("Checking for %s in cache!!!\n", hostname);

  char *cache_line;
  char *temp_buf = calloc(strlen(cacheDNSBuffer) + 1, sizeof(char));
  strcpy(temp_buf, cacheDNSBuffer);

  char *hostname_match = strstr(temp_buf, hostname);
  /* If hostname missing from cache */
  if (hostname_match == NULL)
  {
    return -1;
  }

  cache_line = strtok(hostname_match, ":");
  cache_line = strtok(NULL, "\n");
  printf("Found DNS cache entry %s:%s\n", hostname, cache_line);
  inet_pton(AF_INET, cache_line, cache_addr);
  free(temp_buf);
}

int add_ip_to_cache(char *hostname, char *ip)
{

  pthread_mutex_lock(&dns_lock);

  char *entry = strrchr(cacheDNSBuffer, '\n');
  char buf[100];

  memset(buf, 0, sizeof(buf));
  snprintf(buf, 100, "%s:%s\n", hostname, ip);

  if (entry == NULL)
  {
    printf("Cache empty\n");
    strncpy(cacheDNSBuffer, buf, strlen(buf));
    pthread_mutex_unlock(&dns_lock);
    return 0;
  }
  /* Cache Full */
  if (entry + strlen(buf) + 1 > cacheDNSBuffer + sizeof(cacheDNSBuffer))
  {
    return -1;
    pthread_mutex_unlock(&dns_lock);
  }
  strncpy(entry + 1, buf, strlen(buf));
  pthread_mutex_unlock(&dns_lock);
}


void md5_str(char *str, char *md5buf)
{
  unsigned char MS5_sum[16];
  MD5_CTX context;

  MD5_Init(&context);
  MD5_Update(&context, str, strlen(str));
  MD5_Final(MS5_sum, &context);

  for (int i = 0; i < 16; ++i)
  {
    sprintf(md5buf + i * 2, "%02x", (unsigned int)MS5_sum[i]);
  }
  //printf("Hashed Val\t: %s -> %s\n", str, md5buf);
}