# Access-Control-Logging



## Description

An access control logging system using the C programming language. The access control logging system will monitor and keep track of every file access and
modification that occurs in the system. So, each file access or file modification will generate an entry in a log file. This log file will be inspected by a separate high privileged process.


## Implementation


### Logger

```
logger

To keep track every file access and modifications this library use the log_entry structure

The log_entry structure contains the following fields :

	1. uid : user id (positive integer) 
	2. access_type : access type values [0-2]
	3. action_denied : is action denied values [0-1]
	4. time_t timestamp :  date and time that the action occurred
	5. file : filename (string)
	6. fingerprint : file fingerprint

```


```
write_log_file 
			
This function is responsible to write the log_entry to file_logging file
Because the size of each log_entry is dynamic , the function writes two slashes between the field file and the field fingerprint so that it can read the log_entry
The log entries recorded as hex values
```


```
fopen 
			
This function keep track every file access
This function distinguish the creation ​of a file from the ​opening ​of an existing file using the function access before the original fopen is called
The fingerprint of the file is setting to null either the file does not exist or user has not got read access to file
@return : return the original fopen file pointer
```


```
fwrite 
			
This function keep track every file modification
This function take the name of the file using the realink function with appropriately arguments
The computation of the fingerprint is done after calling the original fwrite 
The function get the results that have been written using the function fflush and after compute the fingerprint
The fingerprint of the file is setting to null when user has not got read access to file
@return : return the original fwrite size_t
```


### Monitor


```
acmonitor 

To implemented the list_unauthorized_accesses and list_file_modifications functions, was used the log_entry structure.

The log_entry structure contains the following fields :

	1. uid : user id (positive integer) 
	2. access_type : access type values [0-2]
	3. action_denied : is action denied values [0-1]
	4. time_t timestamp :  date and time that the action occurred
	5. file : filename (string)
	6. fingerprint : file fingerprint
	7. access_multiple_files : contains the number of different accessed files without permission from each user (used on list_unauthorized_accesses)
	8. accessed_user_files : hyphen separated list of different accessed filenames without permission of user (used on list_unauthorized_accesses)
	9. file_contents_modified : contains the number of times that the file was indeed modified of each user (used on list_file_modifications)

```


```
list_unauthorized_accesses 
			
This function returns all users that tried to access more than 7 different files without having permissions.

```


```
list_file_modifications 
			
This function print a table with the number of times each user has modified the file.
This function use the last_modified_fingerprint string that contains the last modified fingerprint of file 
Used to comparing with fingerprint of the current log_entry so the log_entry which was read at that time and is updated by reading the_logging file when necessary

```


### Testing

```
test_aclog

To demonstrated the above tasks list_unauthorized_accesses and list_file_modifications on this function implemented the following :
	
    1. Created a malicious user who has access to 8 different files without has got permission (list_unauthorized_accesses)
    2. A user who indeed modified the contents of the file user1 two times ( ./acmonitor -i user1 )
    
```


## Tool specifications

```
Options:
    -m Prints malicious users
    -i <filename> Prints table of users that modified the file given and the number of modifications
    -h Help message
```

## Compilation

#### Requirements: Any Linux distribution

#### Compilation: 
  1. make [all]  - to build 
  2. make clean - to remove
