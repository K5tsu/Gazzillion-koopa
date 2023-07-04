#include "../include/encryption_manager.h"

void operate_dir(const char* dir_name, int indent, int mode){
    DIR *dir;
    struct dirent *entry;

    if (!(dir = opendir(dir_name))){
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            char path[1024];
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;
            snprintf(path, sizeof(path), "%s/%s", dir_name, entry->d_name);
            printf("%*s[%s]\n", indent, "", entry->d_name);
            operate_dir(path, indent + 2, mode);
        } else {
            char path[1024];
            snprintf(path, sizeof(path), "%s/%s", dir_name, entry->d_name);
            struct stat path_stat;
            stat(path, &path_stat);
            if(S_ISREG(path_stat.st_mode)){
                printf("%*s- %s\n", indent, "", entry->d_name);
                if(mode == 0){
                    if(toy_encrypt(path)!=0){
                        printf("Error decrypting file %s\n", path);
                    }
                }else if(mode == 1){
                    if(toy_decrypt(path)!=0){
                        printf("Error encrypting file %s\n", path);
                    }
                }
                
            }
            
        }
    }
    closedir(dir);
        

}

int toy_encrypt(const char* file_name){
    char temp_copy_file_name [1024];
    strcpy(temp_copy_file_name, file_name);
    strcat (temp_copy_file_name, ".kop\0");

    FILE *file = fopen(file_name, "r");
    FILE *file_copy = fopen(temp_copy_file_name, "w");
    size_t n = 0;
    int c;

    if (file == NULL || file_copy == NULL){
        return 1;
    }

    while ((c = fgetc(file)) != EOF){
        fputc(~c, file_copy);
    }    

    if(remove(file_name)!=0){
        return 1;
    }

    return 0;
}

int toy_decrypt(const char* file_name){
    char temp_copy_file_name [1024];
    strcpy(temp_copy_file_name, file_name);
    temp_copy_file_name[strlen(temp_copy_file_name)-4] = '\0';

    FILE *file = fopen(file_name, "r");
    FILE *file_copy = fopen(temp_copy_file_name, "w");
    size_t n = 0;
    int c;

    if (file == NULL || file_copy == NULL){
        return 1;
    }

    while ((c = fgetc(file)) != EOF){
        fputc(~c, file_copy);
    }    
    if(remove(file_name)!=0){
        return 1;
    }

    return 0;
}

void main(int argc, char *argv[]){
    char directory[512];
    char mode;

    int opt;
    int dir_provided = 0;
    int mode_provided = 0;
    printf("%s", argv[0]);
    printf("%s", argv[1]);
    printf("%s", argv[2]);
    while ((opt = getopt(argc, argv, ":m:d:")) != -1) {
        switch (opt) {
        case 'd':
            strcpy(directory, optarg);
            dir_provided = 1;
            break;
        case 'm':
            mode = optarg[0];
            mode_provided = 1;
            break;
        default:
            printf("Wrong arguments\n");
            exit(1);
        }
    }

    if(dir_provided==1 && mode_provided==1){
        if(mode == 'E'){
            operate_dir(directory, 0, 0);
        }else if (mode == 'D'){
            operate_dir(directory, 0, 1);
        }
    }else{
        printf("Wrong args selected\n");
        return;
    }
    
}
