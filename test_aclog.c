#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
      
int main() 
{
	int i;
	size_t bytes;
	FILE *file;
	char filenames[10][7] = {"file_0", "file_1", 
			"file_2", "file_3", "file_4",
			"file_5", "file_6", "file_7", 		
			"file_8", "file_9"};


	for (i = 0; i < 10; i++) {

		file = fopen(filenames[i], "w+");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}

	}

	// Malicious users
	for(i = 2; i < 10; i++){

		// Setting Read permissions for User, Group, and Others
		chmod(filenames[i], S_IRUSR|S_IRGRP|S_IROTH);

		// Open
		file = fopen(filenames[i], "a+");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}
	}


	// List of modifications

	// Open file
	file = fopen("user1", "r");
	if (file == NULL) 
		printf("fopen error\n");
	else{
		fclose(file);
	}

	// Else created
	FILE* new_file = fopen("user1", "a+");

	// Modify file 
	bytes = fwrite("user1", strlen("user1"), 1, new_file);
	bytes = fwrite("", strlen(""), 1, new_file);
	bytes = fwrite("user1", strlen("user1"), 1, new_file);

	// Close file
	fclose(new_file);


}
