/*
 * socket-client.c
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

int main(int argc, char *argv[])
{
	int sd, port, ret, i;
	ssize_t n;
	char ch;
	char *hostname;
	struct hostent *hp;
	struct sockaddr_in sa;

	//set of socket descriptors
	fd_set fds;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s hostname port\n", argv[0]);
		exit(1);
	}

	hostname = argv[1];
	port = atoi(argv[2]); /* Needs better error checking */

	/* Create TCP/IP socket, used as main chat channel */
	if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		exit(1);
	}
	fprintf(stderr, "Created TCP socket\n");
	
	/* Look up remote hostname on DNS */
	if ( !(hp = gethostbyname(hostname))) {
		printf("DNS lookup failed for host %s\n", hostname);
		exit(1);
	}

	/* Connect to remote TCP port */
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	memcpy(&sa.sin_addr.s_addr, hp->h_addr, sizeof(struct in_addr));
	fprintf(stderr, "Connecting to remote host... "); fflush(stderr);
	if (connect(sd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
		perror("connect");
		exit(1);
	}
	fprintf(stderr, "Connected.\n");

	int cfd = open("/dev/cryptodev0", O_RDWR);
	if (cfd < 0) {
		perror("open(/dev/cryptodev0)");
		exit(1);
	}


	////////////////////////////////////////////////////////
	/* Be careful with buffer overruns, ensure NUL-termination */
	/*strncpy(buf, HELLO_THERE, sizeof(buf));
	buf[sizeof(buf) - 1] = '\0';*/

	/* Say something... */
	/*if (insist_write(sd, buf, strlen(buf)) != strlen(buf)) {
		perror("write");
		exit(1);
	}
	fprintf(stdout, "I said:\n%s\nRemote says:\n", buf);
	fflush(stdout); */
	/////////////////////////////////////////////////////////


	/* Read answer and write it to standard output */
	for (;;) {

			//clear the socket set
			FD_ZERO(&fds);

			//add socket and stdin to socket set
			FD_SET(sd, &fds);
			FD_SET(0, &fds);

			ret = select(sd+1, &fds, NULL, NULL, NULL);
			if ((ret<0) && (errno!=EINTR)) {
				printf("error in select");
				exit(1);
			}

			if (FD_ISSET(sd, &fds)) {
				
			
				//read from socket and write to stdout
				n = read(sd, buf, sizeof(buf));
				if (n <= 0) {
					if (n < 0)
						perror("read from remote peer failed");
					else
						fprintf(stderr, "Peer went away\n");
					break;
				}
				if(decrypt(cfd)<0) return 1;
				if (insist_write(1, buf, n) != n) {
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
			}
			if(ch=='\n'){
				buf[i] = ch;
				i++;
			}
			buf[i]='\0';
			if(encrypt(cfd)<0) return 1;
			if (insist_write(sd, buf, sizeof(buf)) != sizeof(buf)) { //and copy the buffer to the socket
					perror("write");
					exit(1);
			}		
	
			//clear the buffer
			memset(&buf[0], 0, sizeof(buf));
		}
		}

	/*
	* Let the remote know we're not going to write anything else.
	* Try removing the shutdown() call and see what happens.
	*/
	if (shutdown(sd, SHUT_WR) < 0) {
		perror("shutdown");
		exit(1);
	}
	fprintf(stderr, "\nDone.\n");
	return 0;
}
