#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define FILE_FINGERPRINT_LENGTH 16

typedef struct{

	int uid; /* user id (positive integer) */
	int access_type; /* access type values [0-2] */
	int action_denied; /* is action denied values [0-1] */

	time_t timestamp; /* date and time that the action occurred */

	char *file; /* filename (string) */
	char *fingerprint; /* file fingerprint */

	// List unauthorized accesses
	int access_multiple_files; /* the number of different accessed files wihtout permission */
	char* accessed_user_files; /* hyphen separated list of different accessed filenames wihtout permission */

	// List file modifications
	int file_contents_modified; /* the number of times that the file was indeed modified */

}log_entry;


// Read from log file
log_entry* read_log_file(FILE* pfd){

	// Initialize log entry
	log_entry *logEntry = (log_entry*)malloc(sizeof(log_entry));

	// Initialize str
	char* str = (char*)malloc(sizeof(char)*sizeof(int));

	// Read uid
	if( fread(str,sizeof(int),1,pfd) != 1){
		printf("Error on read uid\n");
	    abort();
	}
	memcpy(&logEntry->uid,str,sizeof(int));

	// Read access_type
	if( fread(str,sizeof(int),1,pfd) != 1){
		printf("Error on read access_type\n");
	    abort();
	}
	memcpy(&logEntry->access_type,str,sizeof(int));

	// Read action_denied flag
	if( fread(str,sizeof(int),1,pfd) != 1){
		printf("Error on read action_denied\n");
	    abort();
	}
	memcpy(&logEntry->action_denied,str,sizeof(int));

	// Read timestamp
	str = realloc(str,sizeof(time_t));
	if( fread(str,sizeof(time_t),1,pfd) != 1){
		printf("Error on read timestamp\n");
	    abort();
	}
	memcpy(&logEntry->timestamp,str,sizeof(time_t));

	// Read filepath
	char* filepath = (char *)malloc(sizeof(char)*1);
	int count = 0;
	int current_char =0;
	int previous = 0;
	do{
	    current_char = fgetc(pfd);

	    if( previous == 47 && current_char == 47 ){ break; }
	    previous = current_char;

	    *(filepath+count) = current_char;
	    count++;
	    filepath = realloc(filepath, count+1);

	}while(1);

	logEntry->file = (char *)malloc(sizeof(char)*count);
	memcpy(logEntry->file,filepath,count-1);
	*(logEntry->file + count-1) = '\0';

	// Read digital fingerprint of file
	logEntry->fingerprint = (unsigned char *)malloc(sizeof(unsigned char)*FILE_FINGERPRINT_LENGTH + 1);
	if( fread(logEntry->fingerprint,FILE_FINGERPRINT_LENGTH,1,pfd) != 1){
		printf("Error on read fingerprint\n");
	    abort();
	}

	*(logEntry->fingerprint + FILE_FINGERPRINT_LENGTH) = '\0';
	
	// Clean up
	free(str);
	free(filepath);

	// Return
	return logEntry;
}


void usage(void){
	printf(
	       "\n"
	       "usage:\n"
	       "\t./monitor \n"
		   "Options:\n"
		   "-m, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}

// Search uid on log_entry_array
int search_array(log_entry** log_entry_array ,int uid,int length_array){

	// User does not exist on log_entry_array
	if(length_array == 0){ return -1; }
	// Search the user
	else{
		for(int i=0;i<length_array;i++){
			if(log_entry_array[i]->uid == uid){ return i;}
		}
		return -1;
	}
}

// Compare two filenames
int different_file(char* filename,char* filename_new){

	char* filename_slash = NULL;
	char* filename_slash_new = NULL;

	filename_slash = strrchr(filename, 47);
	filename_slash_new = strrchr(filename_new, 47);

	// If filename does not contain slash
	if( filename_slash == NULL ){ filename_slash = filename; }
	else{ filename_slash++; }

	// If filename_new does not contain slash
	if( filename_slash_new == NULL ){ filename_slash_new = filename_new; }
	else{ filename_slash_new++; }

	// Compare the filenames
	return strcmp(filename_slash, filename_slash_new);	
}

// Appped filename to accessed user files if not exist and update appropriately the access_multiple_files
char* append_accessed_user_files(char* filename,char* accessed_user_files,int* access_multiple_files){

	if(accessed_user_files == NULL){
		accessed_user_files = (char*)malloc(sizeof(char)*strlen(filename)+1);
		memcpy(accessed_user_files,filename,strlen(filename));
		memset(accessed_user_files+strlen(filename),'-',1*sizeof(char));
		*access_multiple_files = 1;
	}
	else{

		// Get the first token
		char* token = strtok(strdup(accessed_user_files), "-");

		// Walk through other tokens
		while( token != NULL ) {

			// If exist then nothing appened
			if(strcmp(filename,token) == 0){
				return accessed_user_files;
			}

			token = strtok(NULL, "-");
		}

		accessed_user_files = (char*)realloc(accessed_user_files,(strlen(accessed_user_files)+strlen(filename)+2)*sizeof(char));
		strcat(accessed_user_files, filename);
		strcat(accessed_user_files, "-");
		*access_multiple_files = *access_multiple_files + 1;
	}
	return accessed_user_files;
}


void list_unauthorized_accesses(FILE *log){

	log_entry* readLogEntry;
	log_entry** log_entry_array = NULL;
	int count=0;

	do{

		// Read log_entry
		readLogEntry = read_log_file(log);
		readLogEntry->accessed_user_files = NULL;

		// If the action was denied to the user,then insert or update(if exist) the array
		if(readLogEntry->action_denied == 1){

			// Search on log_entry array to find if exitst this user
			int pos;
			if( (pos = search_array(log_entry_array,readLogEntry->uid,count)) != -1 ){

				// Append accessed user file if exist and update appropriate the access_multiple_files
				log_entry_array[pos]->accessed_user_files = append_accessed_user_files(readLogEntry->file,
															log_entry_array[pos]->accessed_user_files,
															&log_entry_array[pos]->access_multiple_files);

				free(readLogEntry);

			}
			else{

				// Add one element to the log entry array
		  		log_entry_array = (log_entry** )realloc(log_entry_array, (count + 1) * sizeof(log_entry*));

				// Allocate memory for one struct log_entry
				log_entry_array[count] = readLogEntry;

				// Append accessed user file if exist and update appropriately the access_multiple_files
				log_entry_array[count]->accessed_user_files = append_accessed_user_files(readLogEntry->file,
															  log_entry_array[count]->accessed_user_files,
															  &log_entry_array[count]->access_multiple_files);

				// Update the count
				count++;
			}
		}
		else{ free(readLogEntry); }

		// Check the end of file
		if( fgetc(log) == EOF){ break; }
		else{ fseek(log,-1,SEEK_CUR); }

	}while(1);
	
	// Search for malicious user and print them
	printf("---------Malicious Users---------\n");
	for(int i = 0; i < count; i++) {
		if(log_entry_array[i]->access_multiple_files > 7){
			printf("[%d] uid: %d\n", (i+1), log_entry_array[i]->uid);
		}
	}
	printf("---------------------------------\n");

	// Free all log_entry_array elements
	for(int i = 0; i < count; i++) {
	  free(log_entry_array[i]->file);
	  free(log_entry_array[i]->fingerprint);
	  free(log_entry_array[i]->accessed_user_files);
	  free(log_entry_array[i]);
	}

	// Clean up
 	free(log_entry_array);
	return;
}


void list_file_modifications(FILE *log, char *file_to_scan){

	log_entry* readLogEntry;
	log_entry** log_entry_array = NULL;
	int count=0;
	char* last_modified_fingerprint = NULL;

	// Null string
	char* null_string = NULL;
	null_string = (char*)malloc(sizeof(char)*FILE_FINGERPRINT_LENGTH);
	memset(null_string,0,FILE_FINGERPRINT_LENGTH);

	do{

		// Read log_entry
		readLogEntry = read_log_file(log);

		// Take only the logs with filename equal to file_to_scan and fingerprint different of null(either has not access permission or file_to_scan initially does not exist)
		if( different_file(readLogEntry->file,file_to_scan) == 0 && strncmp(null_string,readLogEntry->fingerprint,FILE_FINGERPRINT_LENGTH) != 0 ){

			// Search on log_entry array to find if exitst this user
			int pos;
			if( (pos = search_array(log_entry_array,readLogEntry->uid,count)) != -1 ){

				// If action denied flag is false then compare the fingerprints of file
				if( readLogEntry->action_denied == 0 ){

					// Update file_contents_modified if user change actually the contents of file
					if( strncmp(last_modified_fingerprint,readLogEntry->fingerprint,FILE_FINGERPRINT_LENGTH) != 0 ){

						log_entry_array[pos]->file_contents_modified++;

						// Update last modified fingerprint
						memcpy(last_modified_fingerprint,readLogEntry->fingerprint,FILE_FINGERPRINT_LENGTH);
					}

					free(readLogEntry); 
				}
				else{ free(readLogEntry); }	
			}
			else{

				// Add one element to the log entry array
		  		log_entry_array = (log_entry** )realloc(log_entry_array, (count + 1) * sizeof(log_entry*));

				// Allocate memory for one struct log_entry
				log_entry_array[count] = readLogEntry;

				// Initialize accessed_user_files to NULL(not used on this function)
				log_entry_array[count]->accessed_user_files = NULL;

				// Initialize file_contents_modified
				log_entry_array[count]->file_contents_modified = 0;

				// Initialize the initial fingerprint of file as last_modified_fingerprint
				if( count == 0 ){
					last_modified_fingerprint = (char*)malloc(sizeof(char)*FILE_FINGERPRINT_LENGTH+1);
					memcpy(last_modified_fingerprint,readLogEntry->fingerprint,FILE_FINGERPRINT_LENGTH);				
					*(last_modified_fingerprint + FILE_FINGERPRINT_LENGTH) = '\0';
				}
				else{
					
					// Update file_contents_modified if needed for this user
					if( readLogEntry->action_denied == 0 ){

						// Comparison
						if( strncmp(last_modified_fingerprint,readLogEntry->fingerprint,FILE_FINGERPRINT_LENGTH) != 0 ){

							log_entry_array[count]->file_contents_modified++;

							// Update last modified fingerprint
							memcpy(last_modified_fingerprint,readLogEntry->fingerprint,FILE_FINGERPRINT_LENGTH);

						}
					}
				}

				// Update the count
				count++;

			}	
		}
		else{ free(readLogEntry); }	

		// Check the end of file
		if( fgetc(log) == EOF){ break; }
		else{ fseek(log,-1,SEEK_CUR); }

	}while(1);

	// Search for malicious user and print them
	printf("---------------------Users---------------------\n");
	for(int i = 0; i < count; i++) {
		if(log_entry_array[i]->file_contents_modified > 0){
			printf("[%d] uid: %d", (i+1), log_entry_array[i]->uid);
			printf("		   times_modified: %d\n",log_entry_array[i]->file_contents_modified);
		}	
	}
	printf("-----------------------------------------------\n");


	// Free all log_entry_array elements
	for(int i = 0; i < count; i++) {
		free(log_entry_array[i]->file);
		free(log_entry_array[i]->fingerprint);
		free(log_entry_array[i]->accessed_user_files);
		free(log_entry_array[i]);
	}

	// Clean up
 	free(log_entry_array);
 	free(last_modified_fingerprint);
 	free(null_string);
	return;
}


int main(int argc, char *argv[]){

	int ch;
	FILE *log;

	if (argc < 2)
		usage();

	log = fopen("./file_logging.log", "r");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "./log");
		return 1;
	}

	while ((ch = getopt(argc, argv, "hi:m")) != -1) {
		switch (ch) {		
		case 'i':
			list_file_modifications(log, optarg);
			break;
		case 'm':
			list_unauthorized_accesses(log);
			break;
		default:
			usage();
		}

	}

	fclose(log);
	argc -= optind;
	argv += optind;	
	
	return 0;
}
