/*
 * socket-server.c
 * Simple TCP/IP communication using sockets
 *
 */

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "socket-common.h"
#include "cryptodev.h"
#include <fcntl.h>
#include <sys/stat.h>

#define DATA_SIZE 256
#define BLOCK_SIZE 16
#define KEY_SIZE 16

char buf[DATA_SIZE];
static  int encrypt  (int cfd) {  
	struct session_op sess;  
	struct crypt_op cryp;  
	struct {
 		unsigned  char   in[DATA_SIZE], 
		encrypted[DATA_SIZE], 
		decrypted [DATA_SIZE],
		iv [BLOCK_SIZE], 
		key [KEY_SIZE];
	} data;

	memset (& sess,  0,  sizeof(sess)); 
	memset (& cryp,  0,  sizeof(cryp)); 
	memcpy (& data.in, buf,  sizeof(buf));
	memcpy (& data.iv,  "1234567890123456", BLOCK_SIZE ); 
	memcpy (& data.key,  "abcdefghijklmnop", KEY_SIZE );

	sess.cipher  = CRYPTO_AES_CBC; 
	sess.keylen  = KEY_SIZE; 
	sess.key  = data.key;
	
	if  ( ioctl ( cfd, CIOCGSESSION,  & sess )) { 
		perror ( "ioctl(CIOCGSESSION)" );  
		exit(1);
	}

	cryp.ses  = sess.ses; 
	cryp.len  =  sizeof (data.in); 
	cryp.src  = data.in; 
	cryp.dst  = data.encrypted; 
	cryp.iv  = data.iv;
	cryp.op  = COP_ENCRYPT;

	if  (ioctl(cfd, CIOCCRYPT, &cryp)) { 
		perror ( "ioctl(CIOCCRYPT)" );  
		exit(1);
	} 
	memcpy (&buf, data.encrypted,  sizeof(buf));
 	//printf("\nEncrypted data\n");

	/* Finish crypto session */  
	if  ( ioctl (cfd, CIOCFSESSION,  &sess.ses)) {
		perror ( "ioctl(CIOCFSESSION)" );
 		exit(1); 
	}
	
	return  0;
}


static  int decrypt  (int cfd ) {  

	struct session_op sess;  
	struct crypt_op cryp;  struct {
 			unsigned  char   in[DATA_SIZE], 
			encrypted[DATA_SIZE], 
			decrypted[DATA_SIZE],
			iv[BLOCK_SIZE], 
			key[KEY_SIZE];
 	} data;

	memset (&sess,  0, sizeof(sess)); 
	memset (&cryp,  0, sizeof(cryp)); 
	memcpy (&data.in, buf ,  sizeof(buf));
	memcpy (&data.iv, "1234567890123456", BLOCK_SIZE); 
	memcpy (&data.key, "abcdefghijklmnop", KEY_SIZE);
	
	sess.cipher  = CRYPTO_AES_CBC; 
	sess.keylen  = KEY_SIZE; 
	sess.key  = data.key;
 
	if  ( ioctl (cfd, CIOCGSESSION,  &sess )) { 
		perror ( "ioctl(CIOCGSESSION)" );  
		exit(1);
	}

	cryp.ses  = sess.ses; 
	cryp.len  =  sizeof(data.in); 
	cryp.src  = data.in; 
	cryp.dst  = data.decrypted; 
	cryp.iv  = data.iv;
	cryp.op  = COP_DECRYPT;


	if  ( ioctl (cfd, CIOCCRYPT,  &cryp)) { 
		perror ( "ioctl(CIOCCRYPT)" );  
		exit(1);
	} 

	memcpy (&buf, data.decrypted,  sizeof(buf));
 
	//printf("\nDecrypted data\n");
 	
	/* Finish crypto session */  
	if  ( ioctl (cfd, CIOCFSESSION,  &sess.ses)) {
		perror ( "ioctl(CIOCFSESSION)" );
 		exit(1); 
	}
	return  0;
} 

/* Convert a buffer to upercase */
void toupper_buf(char *buf, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		buf[i] = toupper(buf[i]);
}

/* Insist until all of the data has been written */
ssize_t insist_write(int fd, const void *buf, size_t cnt)
{
	ssize_t ret;
	size_t orig_cnt = cnt;
	
	while (cnt > 0) {
	        ret = write(fd, buf, cnt);
	        if (ret < 0)
	                return ret;
	        buf += ret;
	        cnt -= ret;
	}

	return orig_cnt;
}

int main(void)
{
	char ch, cfd;
	char addrstr[INET_ADDRSTRLEN];
	int sd, newsd, ret, i=0;
	ssize_t n;
	socklen_t len;
	struct sockaddr_in sa;
	fd_set fds;	


	/* Make sure a broken connection doesn't kill us */
	signal(SIGPIPE, SIG_IGN);

	/* Create TCP/IP socket, used as main chat channel */
	if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		exit(1);
	}
	fprintf(stderr, "Created TCP socket\n");

	/* Bind to a well-known port */
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(TCP_PORT);
	sa.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(sd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror("bind");
		exit(1);
	}
	fprintf(stderr, "Bound TCP socket to port %d\n", TCP_PORT);

	/* Listen for incoming connections */
	if (listen(sd, TCP_BACKLOG) < 0) {
		perror("listen");
		exit(1);
	}

	/* Loop forever, accept()ing connections */
	for (;;) {
		fprintf(stderr, "Waiting for an incoming connection...\n");

		/* Accept an incoming connection */
		len = sizeof(struct sockaddr_in);
		if ((newsd = accept(sd, (struct sockaddr *)&sa, &len)) < 0) {
			perror("accept");
			exit(1);
		}
		if (!inet_ntop(AF_INET, &sa.sin_addr, addrstr, sizeof(addrstr))) {
			perror("could not format IP address");
			exit(1);
		}
		fprintf(stderr, "Incoming connection from %s:%d\n",
			addrstr, ntohs(sa.sin_port));
			
		cfd = open("/dev/cryptodev0", O_RDWR);
		if (cfd < 0) {
			perror("open(/dev/cryptodev0)");
			exit(1);
		}

		/* We break out of the loop when the remote peer goes away */
		for (;;) {

			//clear the socket set
			FD_ZERO(&fds);

			//add socket and stdin to socket set
			FD_SET(newsd, &fds);
			FD_SET(0, &fds);

			ret = select(newsd+1, &fds, NULL, NULL, NULL);
			if ((ret<0) && (errno!=EINTR)) {
				printf("error in select");
				exit(1);
			}

			if (FD_ISSET(newsd, &fds)) {
			
				//read from socket and write to stdout
				n = read(newsd, buf, sizeof(buf));
				if (n <= 0) {
					if (n < 0)
						perror("read from remote peer failed");
					else
						fprintf(stderr, "Peer went away\n");
					break;
				}
				if(decrypt(cfd)<0) return 1;
				toupper_buf(buf, n); //lowercase to uppercase
				if (insist_write(1, buf, sizeof(buf)) != sizeof(buf)) {
					perror("write to remote peer failed");
					break;
				}
				memset(&buf[0], 0, sizeof(buf));
			}
			//if the stdin is part of the fds set then
			else if (FD_ISSET(0, &fds)) {
			
			//read from input, write to socket
			i=0;
			buf[sizeof(buf)-1]='\0';
			while( read(STDIN_FILENO, &ch, 1) > 0 && (i<sizeof(buf)-1) && ch!='\n') {
				buf[i] = ch;
				i++;
				//insist_write(1,&ch,1);
			}
			if(ch=='\n'){
				buf[i] = ch;
				i++;
				//insist_write(1,&ch,1);
			}
			buf[i]='\0';
			if(encrypt(cfd)<0) return 1;
			if (insist_write(newsd, buf, sizeof(buf)) != sizeof(buf)) { //and copy the buffer to the socket
						perror("write");
						exit(1);
					}
			
					
	
			//clear the buffer
			memset(&buf[0], 0, sizeof(buf));
		}
		}
		/* Make sure we don't leak open files */
		if (close(newsd) < 0)
			perror("close");
	}

	/* This will never happen */
	return 1;
}

