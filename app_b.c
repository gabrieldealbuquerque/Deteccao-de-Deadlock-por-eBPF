/* SPDX-License-Identifier: MIT
 * App B: escuta 8082, conecta a A:8081; depois bloqueia em recv().
 */
 #define _GNU_SOURCE
 #include <arpa/inet.h>
 #include <errno.h>
 #include <fcntl.h>
 #include <netinet/in.h>
 #include <netinet/tcp.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <sys/socket.h>
 #include <sys/types.h>
 #include <unistd.h>
 
 #define LISTEN_PORT 8082
 #define PEER_DEFAULT "172.28.0.2"
 #define PEER_PORT 8081
 #define SLEEP_BETWEEN_MS 20
 
 static void set_keepalive(int fd) {
   int y = 1, idle = 1, intvl = 1, cnt = 3;
   (void)setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &y, sizeof(y));
   (void)setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
   (void)setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
   (void)setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));
 }
 
 int main(void) {
   const char *peer = getenv("PEER_IP");
   if (!peer || !*peer)
     peer = PEER_DEFAULT;
   int ls = socket(AF_INET, SOCK_STREAM, 0);
   if (ls < 0) {
     perror("socket listen");
     return 1;
   }
   int opt = 1;
   (void)setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
   struct sockaddr_in la = {0};
   la.sin_family = AF_INET;
   la.sin_addr.s_addr = htonl(INADDR_ANY);
   la.sin_port = htons(LISTEN_PORT);
   if (bind(ls, (struct sockaddr *)&la, sizeof(la)) < 0) {
     perror("bind 8082");
     close(ls);
     return 1;
   }
   if (listen(ls, 1) < 0) {
     perror("listen");
     close(ls);
     return 1;
   }
   printf("[App B] Escutando na porta %d, originando ligação para %s:%d\n",
          LISTEN_PORT, peer, PEER_PORT);
   fflush(stdout); // Limpa o buffer de impressão
 
   int out = -1, inc = -1;
   for (;;) {
     if (out < 0) {
       out = socket(AF_INET, SOCK_STREAM, 0);
       if (out < 0) {
         perror("socket out");
         sleep(1);
         continue;
       }
       set_keepalive(out);
       struct sockaddr_in p = {0};
       p.sin_family = AF_INET;
       p.sin_port = htons(PEER_PORT);
       if (inet_pton(AF_INET, peer, &p.sin_addr) != 1) {
         fprintf(stderr, "[App B] inet_pton: IP inválido: %s\n", peer);
         return 1;
       }
       if (connect(out, (struct sockaddr *)&p, sizeof(p)) < 0) {
         if (errno != ECONNREFUSED && errno != ETIMEDOUT && errno != EHOSTUNREACH)
           perror("connect to A:8081");
         close(out);
         out = -1;
         usleep(1000 * SLEEP_BETWEEN_MS);
         continue;
       }
       printf("[App B] Ligação de saída para A estabelecida (ESTABLISHED)\n");
       fflush(stdout); // Limpa o buffer de impressão
     }
     if (inc < 0) {
       int fl = fcntl(ls, F_GETFL, 0);
       fcntl(ls, F_SETFL, fl | O_NONBLOCK);
       struct sockaddr_in c;
       socklen_t clen = sizeof(c);
       int cfd = accept(ls, (struct sockaddr *)&c, &clen);
       fcntl(ls, F_SETFL, fl);
       if (cfd < 0) {
         if (out >= 0)
           usleep(1000 * SLEEP_BETWEEN_MS);
         continue;
       }
       set_keepalive(cfd);
       char ip[64];
       inet_ntop(AF_INET, &c.sin_addr, ip, sizeof(ip));
       printf("[App B] Aceitou ligação de A desde %s:%d (ESTABLISHED)\n", ip,
              (int)ntohs(c.sin_port));
       fflush(stdout); // Limpa o buffer de impressão
       inc = cfd;
     }
     if (out >= 0 && inc >= 0) {
       printf(
           "[App B] As duas ligações ativas. Entrando em recv() bloqueante "
           "(espera circular)\n");
       fflush(stdout); // Limpa o buffer de impressão
 
       char buf[256];
       ssize_t r = recv(out, buf, sizeof(buf), 0);
       
       if (r < 0) {
         perror("\n[App B] recv (saída para A) quebrado pelo pacote RST");
       } else if (r == 0) {
         printf("\n[App B] recv: peer fechou (FIM: conexão encerrada)\n");
       } else {
         printf("\n[App B] recv: recebidos %zd bytes (inesperado no impasse puro)\n", r);
       }
       fflush(stdout); // Limpa o buffer de impressão
       
       if (r <= 0)
         break;
     }
   }
   if (out >= 0)
     close(out);
   if (inc >= 0)
     close(inc);
   close(ls);
   return 0;
 }