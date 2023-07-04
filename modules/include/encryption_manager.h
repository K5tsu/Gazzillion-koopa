#ifndef HEADER_ENCRYPTION_MANAGER
#define HEADER_ENCRYPTION_MANAGER

#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <stdlib.h>
void operate_dir(const char* dir_name, int indent, int mode);
int toy_encrypt(const char* file);
int toy_decrypt(const char* file);

#endif
