#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>

#define BLOCK_SIZE 256 * 1024 // 256 KB
#define MAX_FILES 100 
#define MAX_FILENAME_LENGTH 256
#define MAX_BLOCKS_PER_FILE 64 
#define MAX_BLOCKS MAX_BLOCKS_PER_FILE * MAX_FILES

typedef struct {
    char filename[MAX_FILENAME_LENGTH];
    size_t size;
    size_t blocks[MAX_BLOCKS_PER_FILE];
    size_t num_blocks; 
} FileData;

typedef struct {
    FileData files[MAX_FILES];
    size_t num_files;
    size_t free_blocks[MAX_BLOCKS];
    size_t num_free_blocks;
} FileAllocationTable;

typedef struct {
    unsigned char data[BLOCK_SIZE];
} DiskBlock; 

struct CommandFlags {
    bool create_mode;
    bool extract_mode;
    bool list_mode;
    bool delete_mode;
    bool update_mode;
    bool verbose_mode;
    bool extra_verbose_mode;
    bool is_file;
    bool append_mode;
    bool pack_mode;
    char *outputFile;
    char **inputFiles;
    int numInputFiles;
};

size_t find_free_block(FileAllocationTable *fat) {
    for (size_t i = 0; i < fat->num_free_blocks; i++) {
        if (fat->free_blocks[i] != 0) {
            size_t free_block = fat->free_blocks[i];
            fat->free_blocks[i] = 0;
            return free_block;
        }
    }
    return (size_t)-1;
}

void expand_storage(FILE *storage, FileAllocationTable *fat) {
    fseek(storage, 0, SEEK_END);
    size_t current_size = ftell(storage);
    size_t expanded_size = current_size + BLOCK_SIZE;
    ftruncate(fileno(storage), expanded_size);
    fat->free_blocks[fat->num_free_blocks++] = current_size;
}

void show_archive_contents(const char *packed_file, bool verbose) {
    FILE *archive = fopen(packed_file, "rb");
    if (archive == NULL) {
        fprintf(stderr, "Error al abrir el archivo empaquetado.\n");
        return;
    }

    FileAllocationTable fat;
    fread(&fat, sizeof(FileAllocationTable), 1, archive);

    printf("Contenido del archivo empaquetado:\n");
    printf("-----------------------------------\n");

    for (size_t i = 0; i < fat.num_files; i++) {
        FileData entry = fat.files[i];
        printf("%s\t%zu bytes\n", entry.filename, entry.size);

        if (verbose) {
            printf("  Bloques: ");
            for (size_t j = 0; j < entry.num_blocks; j++) {
                printf("%zu ", entry.blocks[j]);
            }
            printf("\n");
        }
    }

    fclose(archive);
}

void write_disk_block(FILE *archive, DiskBlock *block, size_t position) {
    fseek(archive, position, SEEK_SET);
    fwrite(block, sizeof(DiskBlock), 1, archive);
}

void update_file_allocation_table(FileAllocationTable *fat, const char *filename, size_t size, size_t block_position, size_t bytes_read) {
    for (size_t i = 0; i < fat->num_files; i++) {
        if (strcmp(fat->files[i].filename, filename) == 0) {
            fat->files[i].blocks[fat->files[i].num_blocks++] = block_position;
            fat->files[i].size += bytes_read;
            return;
        }
    }

    FileData new_entry;
    strncpy(new_entry.filename, filename, MAX_FILENAME_LENGTH);
    new_entry.size = size + bytes_read;
    new_entry.blocks[0] = block_position;
    new_entry.num_blocks = 1;
    fat->files[fat->num_files++] = new_entry;
}

void write_file_allocation_table(FILE *archive, FileAllocationTable *fat) {
    fseek(archive, 0, SEEK_SET);
    fwrite(fat, sizeof(FileAllocationTable), 1, archive);
}

void generate_archive(struct CommandFlags options) {
    if (options.verbose_mode) printf("Generando archivo %s\n", options.outputFile);
    FILE *archive = fopen(options.outputFile, "wb");

    if (archive == NULL) {
        fprintf(stderr, "Error al abrir el archivo %s\n", options.outputFile);
        exit(1);
    }

    FileAllocationTable fat; 
    memset(&fat, 0, sizeof(FileAllocationTable)); 

    fat.free_blocks[0] = sizeof(FileAllocationTable); 
    fat.num_free_blocks = 1; 

    fwrite(&fat, sizeof(FileAllocationTable), 1, archive); 

    if (options.is_file && options.numInputFiles > 0) {
        for (int i = 0; i < options.numInputFiles; i++) {
            FILE *input_file = fopen(options.inputFiles[i], "rb"); 
            if (input_file == NULL) {
                fprintf(stderr, "Error al abrir el archivo %s\n", options.inputFiles[i]);
                exit(1);
            }

            if (options.verbose_mode) printf("Agregando archivo %s\n", options.inputFiles[i]);
            size_t file_size = 0; 
            size_t block_count = 0; 
            DiskBlock block; 
            size_t bytes_read; 

            while ((bytes_read = fread(&block, 1, sizeof(DiskBlock), input_file)) > 0) {
                size_t block_position = find_free_block(&fat); 
                if (block_position == (size_t)-1) {
                    if (options.extra_verbose_mode) {
                        printf("No hay bloques libres, ampliando el archivo\n");
                    }
                    expand_storage(archive, &fat); 
                    block_position = find_free_block(&fat); 
                    if (options.extra_verbose_mode) {
                        printf("Nuevo bloque libre en la posición %zu\n", block_position);
                    }
                }

                if (bytes_read < sizeof(DiskBlock)) {
                    memset((char*)&block + bytes_read, 0, sizeof(DiskBlock) - bytes_read); 
                }

                write_disk_block(archive, &block, block_position); 
                update_file_allocation_table(&fat, options.inputFiles[i], file_size, block_position, bytes_read); 

                file_size += bytes_read;
                block_count++;

                if (options.extra_verbose_mode) {
                    printf("Escribiendo bloque %zu para archivo %s\n", block_position, options.inputFiles[i]);
                }
            }

            if (options.verbose_mode) printf("Tamaño del archivo %s: %zu bytes\n", options.inputFiles[i], file_size);

            fclose(input_file);
        }
    } else {
        if (options.verbose_mode) {
            printf("Leyendo datos desde la entrada estándar (stdin)\n");
        }

        size_t file_size = 0;
        size_t block_count = 0;
        DiskBlock block;
        size_t bytes_read;
        while ((bytes_read = fread(&block, 1, sizeof(DiskBlock), stdin)) > 0) {
            size_t block_position = find_free_block(&fat);
            if (block_position == (size_t)-1) {
                expand_storage(archive, &fat);
                block_position = find_free_block(&fat);
            }

            if (bytes_read < sizeof(DiskBlock)) {
                memset((char*)&block + bytes_read, 0, sizeof(DiskBlock) - bytes_read);
            }

            write_disk_block(archive, &block, block_position);
            update_file_allocation_table(&fat, "stdin", file_size, block_position, bytes_read);

            bytes_read += sizeof(DiskBlock);
            block_count++;

            if (options.extra_verbose_mode) {
                printf("Bloque %zu leído desde stdin y escrito en la posición %zu\n", block_count, block_position);
            }
        }
    }

    write_file_allocation_table(archive, &fat);
    fclose(archive);
}

void extract_files_from_archive(const char *packed_file, bool verbose, bool very_verbose) {
    FILE *archive = fopen(packed_file, "rb");
    if (archive == NULL) {
        fprintf(stderr, "Error al abrir el archivo empaquetado.\n");
        return;
    }

    FileAllocationTable fat;
    fread(&fat, sizeof(FileAllocationTable), 1, archive);

    for (size_t i = 0; i < fat.num_files; i++) {
        FileData entry = fat.files[i];
        FILE *output_file = fopen(entry.filename, "wb");
        if (output_file == NULL) {
            fprintf(stderr, "Error al crear el archivo de salida: %s\n", entry.filename);
            continue;
        }

        if (verbose) {
            printf("Extrayendo archivo: %s\n", entry.filename);
        }

        size_t file_size = 0;
        for (size_t j = 0; j < entry.num_blocks; j++) {
            DiskBlock block;
            fseek(archive, entry.blocks[j], SEEK_SET);
            fread(&block, sizeof(DiskBlock), 1, archive);

            size_t bytes_to_write = (file_size + sizeof(DiskBlock) > entry.size) ? entry.size - file_size : sizeof(DiskBlock);
            fwrite(&block, 1, bytes_to_write, output_file);

            file_size += bytes_to_write;

            if (very_verbose) {
                printf("Bloque %zu del archivo %s extraído de la posición %zu\n", j + 1, entry.filename, entry.blocks[j]);
            }
        }

        fclose(output_file);
    }

    fclose(archive);
}

void remove_files_from_archive(const char *packed_file, char **filenames, int num_files, bool verbose, bool very_verbose) {
    FILE *archive = fopen(packed_file, "rb+");
    if (archive == NULL) {
        fprintf(stderr, "Error al abrir el archivo empaquetado.\n");
        return;
    }

    FileAllocationTable fat;
    fread(&fat, sizeof(FileAllocationTable), 1, archive);

    for (int i = 0; i < num_files; i++) {
        const char *filename = filenames[i];
        bool file_found = false;

        for (size_t j = 0; j < fat.num_files; j++) {
            if (strcmp(fat.files[j].filename, filename) == 0) {
                file_found = true;

                for (size_t k = 0; k < fat.files[j].num_blocks; k++) {
                    fat.free_blocks[fat.num_free_blocks++] = fat.files[j].blocks[k];
                    if (very_verbose) {
                        printf("Bloque %zu del archivo '%s' marcado como libre.\n", fat.files[j].blocks[k], filename);
                    }
                }

                for (size_t k = j; k < fat.num_files - 1; k++) {
                    fat.files[k] = fat.files[k + 1];
                }
                fat.num_files--;

                if (verbose) {
                    printf("Archivo '%s' eliminado del archivo empaquetado.\n", filename);
                }

                break;
            }
        }

        if (!file_found) {
            fprintf(stderr, "Archivo '%s' no encontrado en el archivo empaquetado.\n", filename);
        }
    }

    fseek(archive, 0, SEEK_SET);
    fwrite(&fat, sizeof(FileAllocationTable), 1, archive);

    fclose(archive);
}

void modify_files_in_archive(const char *packed_file, char **filenames, int num_files, bool verbose, bool very_verbose) {
    FILE *archive = fopen(packed_file, "rb+");
    if (archive == NULL) {
        fprintf(stderr, "Error al abrir el archivo empaquetado.\n");
        return;
    }

    FileAllocationTable fat;
    fread(&fat, sizeof(FileAllocationTable), 1, archive);

    for (int i = 0; i < num_files; i++) {
        const char *filename = filenames[i];
        bool file_found = false;

        for (size_t j = 0; j < fat.num_files; j++) {
            if (strcmp(fat.files[j].filename, filename) == 0) {
                file_found = true;

                for (size_t k = 0; k < fat.files[j].num_blocks; k++) {
                    fat.free_blocks[fat.num_free_blocks++] = fat.files[j].blocks[k];
                    if (very_verbose) {
                        printf("Bloque %zu del archivo '%s' marcado como libre.\n", fat.files[j].blocks[k], filename);
                    }
                }

                FILE *input_file = fopen(filename, "rb");
                if (input_file == NULL) {
                    fprintf(stderr, "Error al abrir el archivo de entrada: %s\n", filename);
                    continue;
                }

                size_t file_size = 0;
                size_t block_count = 0;
                DiskBlock block;
                size_t bytes_read;
                while ((bytes_read = fread(&block, 1, sizeof(DiskBlock), input_file)) > 0) {
                    size_t block_position = find_free_block(&fat);
                    if (block_position == (size_t)-1) {
                        expand_storage(archive, &fat);
                        block_position = find_free_block(&fat);
                    }

                    write_disk_block(archive, &block, block_position);
                    fat.files[j].blocks[block_count++] = block_position;

                    file_size += bytes_read;

                    if (very_verbose) {
                        printf("Bloque %zu del archivo '%s' actualizado en la posición %zu\n", block_count, filename, block_position);
                    }
                }

                fat.files[j].size = file_size;
                fat.files[j].num_blocks = block_count;

                fclose(input_file);

                if (verbose) {
                    printf("Archivo '%s' actualizado en el archivo empaquetado.\n", filename);
                }

                break;
            }
        }

        if (!file_found) {
            fprintf(stderr, "Archivo '%s' no encontrado en el archivo empaquetado.\n", filename);
        }
    }

    fseek(archive, 0, SEEK_SET);
    fwrite(&fat, sizeof(FileAllocationTable), 1, archive);

    fclose(archive);
}

void compact_archive(const char *packed_file, bool verbose, bool very_verbose) {
    FILE *archive = fopen(packed_file, "rb+");
    if (archive == NULL) {
        fprintf(stderr, "Error al abrir el archivo empaquetado.\n");
        return;
    }

    FileAllocationTable fat;
    fread(&fat, sizeof(FileAllocationTable), 1, archive);

    size_t new_block_position = sizeof(FileAllocationTable);
    for (size_t i = 0; i < fat.num_files; i++) {
        FileData *entry = &fat.files[i];
        size_t file_size = 0;

        for (size_t j = 0; j < entry->num_blocks; j++) {
            DiskBlock block;
            fseek(archive, entry->blocks[j], SEEK_SET);
            fread(&block, sizeof(DiskBlock), 1, archive);

            fseek(archive, new_block_position, SEEK_SET);
            fwrite(&block, sizeof(DiskBlock), 1, archive);

            entry->blocks[j] = new_block_position;
            new_block_position += sizeof(DiskBlock);
            file_size += sizeof(DiskBlock);

            if (very_verbose) {
                printf("Bloque %zu del archivo '%s' movido a la posición %zu\n", j + 1, entry->filename, entry->blocks[j]);
            }
        }

        if (verbose) {
            printf("Archivo '%s' compactado.\n", entry->filename);
        }
    }

    fat.num_free_blocks = 0;
    size_t remaining_space = new_block_position;
    while (remaining_space < fat.free_blocks[fat.num_free_blocks - 1]) {
        fat.free_blocks[fat.num_free_blocks++] = remaining_space;
        remaining_space += sizeof(DiskBlock);
    }

    fseek(archive, 0, SEEK_SET);
    fwrite(&fat, sizeof(FileAllocationTable), 1, archive);

    ftruncate(fileno(archive), new_block_position);

    fclose(archive);
}

void add_files_to_archive(const char *packed_file, char **filenames, int num_files, bool verbose, bool very_verbose) {
    FILE *archive = fopen(packed_file, "rb+");
    if (archive == NULL) {
        fprintf(stderr, "Error al abrir el archivo empaquetado.\n");
        return;
    }

    FileAllocationTable fat;
    fread(&fat, sizeof(FileAllocationTable), 1, archive);

    if (num_files == 0) {
        // Leer desde la entrada estándar (stdin)
        char *filename = "stdin";
        size_t file_size = 0;
        size_t block_count = 0;
        size_t bytes_read = 0; 
        DiskBlock block;
        while ((bytes_read = fread(&block, 1, sizeof(DiskBlock), stdin)) > 0) {
            size_t block_position = find_free_block(&fat);
            if (block_position == (size_t)-1) {
                expand_storage(archive, &fat);
                block_position = find_free_block(&fat);
            }

            write_disk_block(archive, &block, block_position);
            update_fat(&fat, filename, file_size, block_position, bytes_read);

            file_size += bytes_read;
            block_count++;

            if (very_verbose) {
                printf("Bloque %zu leído desde stdin y agregado en la posición %zu\n", block_count, block_position);
            }
        }

        if (verbose) {
            printf("Contenido de stdin agregado al archivo empaquetado como '%s'.\n", filename);
        }
    } else {
        // Agregar archivos especificados
        for (int i = 0; i < num_files; i++) {
            const char *filename = filenames[i];
            FILE *input_file = fopen(filename, "rb");
            if (input_file == NULL) {
                fprintf(stderr, "Error al abrir el archivo de entrada: %s\n", filename);
                continue;
            }

            size_t file_size = 0;
            size_t bytes_read = 0;
            size_t block_count = 0;
            DiskBlock block;
            while ((bytes_read = fread(&block, 1, sizeof(DiskBlock), input_file)) > 0) {
                size_t block_position = find_free_block(&fat);
                if (block_position == (size_t)-1) {
                    expand_storage(archive, &fat);
                    block_position = find_free_block(&fat);
                }

                write_disk_block(archive, &block, block_position);
                update_fat(&fat, filename, file_size, block_position, bytes_read);

                file_size += bytes_read;
                block_count++;

                if (very_verbose) {
                    printf("Bloque %zu del archivo '%s' agregado en la posición %zu\n", block_count, filename, block_position);
                }
            }

            fclose(input_file);

            if (verbose) {
                printf("Archivo '%s' agregado al archivo empaquetado.\n", filename);
            }
        }
    }

    fseek(archive, 0, SEEK_SET);
    fwrite(&fat, sizeof(FileAllocationTable), 1, archive);

    fclose(archive);
}

int main(int argc, char *argv[]) {
    struct CommandFlags flags = {false, false, false, false, false, false, false, false, false, false, NULL, NULL, 0};
    int opt;

    static struct option long_options[] = {
        {"create",      no_argument,       0, 'c'},
        {"extract",     no_argument,       0, 'x'},
        {"list",        no_argument,       0, 'l'},
        {"delete",      no_argument,       0, 'd'},
        {"update",      no_argument,       0, 'u'},
        {"verbose",     no_argument,       0, 'v'},
        {"file",        no_argument,       0, 'f'},
        {"append",      no_argument,       0, 'a'},
        {"pack",        no_argument,       0, 'p'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "cxlduvfap", long_options, NULL)) != -1) {
        switch (opt) {
            case 'c':
                flags.create_mode = true;
                break;
            case 'x':
                flags.extract_mode = true;
                break;
            case 'l':
                flags.list_mode = true;
                break;
            case 'd':
                flags.delete_mode = true;
                break;
            case 'u':
                flags.update_mode = true;
                break;
            case 'v':
                if (flags.verbose_mode) {
                    flags.extra_verbose_mode = true;
                }
                flags.verbose_mode = true;
                break;
            case 'f':
                flags.is_file = true;
                break;
            case 'a':
                flags.append_mode = true;
                break;
            case 'p':
                flags.pack_mode = true;
                break;
            default:
                fprintf(stderr, "Usage: %s [-cxlduvfap] <outputFile> <inputFile1> ... <inputFileN>\n", argv[0]);
                return 1;
        }
    }

    if (optind < argc) {
        flags.outputFile = argv[optind++];
    }

    flags.numInputFiles = argc - optind;
    if (flags.numInputFiles > 0) {
        flags.inputFiles = &argv[optind];
    }

    if (flags.create_mode) generate_archive(flags); 
    else if (flags.extract_mode) extract_files_from_archive(flags.outputFile, flags.verbose_mode, flags.extra_verbose_mode);
    else if (flags.delete_mode) remove_files_from_archive(flags.outputFile, flags.inputFiles, flags.numInputFiles, flags.verbose_mode, flags.extra_verbose_mode);
    else if (flags.update_mode) modify_files_in_archive(flags.outputFile, flags.inputFiles, flags.numInputFiles, flags.verbose_mode, flags.extra_verbose_mode);
    else if (flags.append_mode) add_files_to_archive(flags.outputFile, flags.inputFiles, flags.numInputFiles, flags.verbose_mode, flags.extra_verbose_mode);

    if (flags.pack_mode) compact_archive(flags.outputFile, flags.verbose_mode, flags.extra_verbose_mode);
    if (flags.list_mode) show_archive_contents(flags.outputFile, flags.verbose_mode);

    return 0;
}

