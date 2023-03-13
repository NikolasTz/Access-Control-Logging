#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/md5.h>
#include <fcntl.h>
#include <limits.h>

typedef struct{
	
	int uid; /* user id (positive integer) */
	int access_type; /* access type values [0-2] */
	int action_denied; /* is action denied values [0-1] */

	time_t timestamp; /* date and time that the action occurred */

	char *file; /* filename (string) */
	unsigned char *fingerprint; /* file fingerprint */

}log_entry;


void write_log_file(log_entry *logEntry){

	// Open file_logging.log
	int pfd;
	if ( (pfd = open("./file_logging.log", O_RDWR  | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)) == -1 ){
	    printf("Cannot open file_logging.log file\n");
	    abort();
	}

	// Write uid
	if( ( write(pfd,&logEntry->uid,sizeof(int)) ) == -1){
		printf("Error on write \n");
	    abort();
	}

	// Write access_type
	if( ( write(pfd,&logEntry->access_type,sizeof(int)) ) == -1){
		printf("Error on write \n");
	    abort();
	}

	// Write action_denied flag
	if( ( write(pfd,&logEntry->action_denied,sizeof(int)) ) == -1){
		printf("Error on write \n");
	    abort();
	}

	// Write timestamp of event
	if( ( write(pfd,&logEntry->timestamp,sizeof(time_t)) ) == -1){
		printf("Error on write \n");
	    abort();
	}

	// Write filepath
	if( ( write(pfd,logEntry->file,strlen(logEntry->file)) ) == -1){
		printf("Error on write \n");
	    abort();
	}

	// Write slashes as seperator between filepath and message digest 
	char* slash = malloc(sizeof(char)*2);
	memset(slash,47,sizeof(char)*2);

	if( ( write(pfd,slash,2*sizeof(char)) ) == -1){
		printf("Error on write \n");
	    abort();
	}

	// Write digital fingerprint of file
	if( ( write(pfd,logEntry->fingerprint,MD5_DIGEST_LENGTH) ) == -1){
		printf("Error on write \n");
	    abort();
	}

	// Clean up
	free(slash);

	// Close file descriptor
	close(pfd);
}


FILE *fopen(const char *path, const char *mode){

	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	log_entry* logEntry = (log_entry*)malloc(sizeof(log_entry));

	// Get the user id
	logEntry->uid = (int)getuid();

	// Get the date and time that the action occurred
	logEntry->timestamp = time(NULL);

	// Identify access type using fopen

	// File creation or file does not exist 
	if ( access(path,F_OK) != 0 ){

		// Access type
		logEntry->access_type = 0;

		// Action denied
		logEntry->action_denied = 0;

		// File name 
		logEntry->file = (char*)malloc(sizeof(char)*strlen(path));
		memcpy(logEntry->file,path,strlen(path)); 

		// File fingerprint
		logEntry->fingerprint = NULL;
	}	
	// File open	
	else {

		// Access type
		logEntry->access_type = 1;

		// Get status of file using stat
	   	struct stat* sb = (struct stat*)malloc(sizeof(struct stat));
	   	if ( stat(path,sb) != 0 ){
			printf("Error on stat\n");
			abort();
		}

		// Action denied
		// If mode contain + , then user must have write and read access privileges
	   	if( strrchr(mode,'+') != NULL ){

	   		// Check the user access privileges and set appropriately the action_denied
	   		logEntry->action_denied = ((sb->st_mode & S_IRUSR) && (sb->st_mode & S_IWUSR)) ? 0 : 1;
	   	}
	   	else{

	   		// Write access only
	   		if( ( strchr(mode,'a') != NULL) || ( strchr(mode,'w') != NULL) ){
	   				
	   			// Check the user access privileges and set appropriately the action_denied
	   			logEntry->action_denied = (sb->st_mode & S_IWUSR) ? 0 : 1;
	   		}

	   		// Read access only
	   		if( strchr(mode,'r') != NULL ){
	   				
	   			// Check the user access privileges and set appropriately the action_denied
	   			logEntry->action_denied = (sb->st_mode & S_IRUSR) ? 0 : 1;
	   		}
	   	}

		// File name 
		logEntry->file = realpath(path, NULL);

	   	// File fingerprint
	   	logEntry->fingerprint = NULL;

		free(sb);
	}

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);

	// Fingerprint of file
	// Initialize fingerprint
	logEntry->fingerprint = (unsigned char*)malloc(MD5_DIGEST_LENGTH);

	// File created or opened
	if( access(path,F_OK) == 0 ){


		// Get status of file using stat
	   	struct stat* sb_new = (struct stat*)malloc(sizeof(struct stat));
	   	if ( stat(path,sb_new) != 0 ){
			printf("Error on stat\n");
			abort();
		}

		// If have read access
		if( (sb_new->st_mode & S_IRUSR) ){

   			unsigned char* read_string = (unsigned char*)malloc(sizeof(unsigned char)*((int)sb_new->st_size)+1);
   			memset(read_string,0,sb_new->st_size+1);

   			// Open the file
   			int fd = open(path,O_RDONLY); 

   			// Read from file 
   			read(fd,read_string, sb_new->st_size); 

   			// Initialize digital file fingerprint
		    unsigned char* md = (unsigned char*)malloc(MD5_DIGEST_LENGTH);

		    // Compute the message digest
		    MD5(read_string,sb_new->st_size,md);

		    // Copy message digest to logEntry fingerprint
		    memcpy(logEntry->fingerprint,md,MD5_DIGEST_LENGTH);

		    free(read_string);
		    free(md);
		    close(fd);
	   	}
	   	else{ memset(logEntry->fingerprint,0,MD5_DIGEST_LENGTH); }

		free(sb_new);
	}
	// File does not exist
	else{ memset(logEntry->fingerprint,0,MD5_DIGEST_LENGTH); }

	// Write log entry
	write_log_file(logEntry);

	// Clean up
	free(logEntry->fingerprint);
	free(logEntry->file);
	free(logEntry);

	return original_fopen_ret;
}


size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream){

	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);	

	// Initialize log_entry
	log_entry* logEntry = (log_entry*)malloc(sizeof(log_entry));

	// Get the user id
	logEntry->uid = (int)getuid();

	// Get the date and time that the action occurred
	logEntry->timestamp = time(NULL);

	// Access type
	logEntry->access_type = 2;

	/* call the original fwrite function */
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);

	// Get file descriptor using stream
	int fds = fileno(stream);

	// Get status of file using fstat
	struct stat* sb = (struct stat*)malloc(sizeof(struct stat));
	if ( fstat(fds,sb) != 0 ){
		printf("Error on fstat\n");
		abort();
	}

	// Action denied flag
	logEntry->action_denied = (sb->st_mode & S_IWUSR) ? 0 : 1;

	// Get file path
	char* proclnk = (char *)malloc(sizeof(char)*18);
	sprintf(proclnk, "/proc/self/fd/%d", fds);
	char* file = (char*)malloc(sizeof(char)*PATH_MAX);
	size_t path_bytes;

    if ( (path_bytes = readlink(proclnk, file, PATH_MAX)) < 0){
        printf("Failed to readlink\n");
        abort();
    }

    // Copy file path to log_entry file field
    logEntry->file = (char*)malloc(sizeof(char)*path_bytes + 1);
    memcpy(logEntry->file,file,path_bytes);
    *(logEntry->file + path_bytes) = '\0';

    // Clean up
    free(proclnk);
	free(file);

	// File fingerprint 

	// Flush the stream buffer so that writted the result to file
	fflush(stream);

	// Get status of file using fstat after calling the original fwrite
	if ( fstat(fds,sb) != 0 ){
		printf("Error on fstat\n");
		abort();
	}

	// Compute fingerprint

	// Initialize fingerprint
	logEntry->fingerprint = (unsigned char*)malloc(MD5_DIGEST_LENGTH);

   	// If user have got read access
	if( (sb->st_mode & S_IRUSR) ){

		unsigned char* read_string = (unsigned char*)malloc(sizeof(unsigned char)*((int)sb->st_size)+1);

		// Open the file
		int fd = open(logEntry->file,O_RDONLY); 

		// Read from file 
		read(fd,read_string, sb->st_size); 

		// Add backslash to read_string
		*(read_string+sb->st_size) = '\0';

		// Initialize digital file fingerprint
	    unsigned char* md = (unsigned char*)malloc(MD5_DIGEST_LENGTH);

	    // Compute the message digest
	    MD5(read_string,sb->st_size,md);

	    // Copy message digest to logEntry fingerprint
	    memcpy(logEntry->fingerprint,md,MD5_DIGEST_LENGTH);

	    free(read_string);
	    free(md);
	    close(fd);
   	}
   	else{ memset(logEntry->fingerprint,0,MD5_DIGEST_LENGTH); }


	// Write log entry
	write_log_file(logEntry);


	free(sb);
	free(logEntry->fingerprint);
	free(logEntry->file);
	free(logEntry);

	return original_fwrite_ret;
}
