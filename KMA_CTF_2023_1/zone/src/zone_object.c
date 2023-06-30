

#include "libzone.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>

#define MAX_COUNT 0x400
#define INTEGER 1
#define BUFFER  2

struct value {
    size_t val;
    size_t len;
    char * buf;
    size_t refcount;
    int type;
};

struct object {
    struct value * id;
    struct value * name;
};

struct object_entry {
    bool available;
    struct object * ptr;
};

size_t cnt;
struct object_entry db[MAX_COUNT];

int read_int() {
    char buf[20];
    memset(buf, 0, 20);
    read(0, buf, 10);
    return atoi(buf);
}

void free_value(struct value * v) {
    if (!--v->refcount) {
        if (v->type == BUFFER) {
            zfree(v->buf, v->len);
        }
        memset(v->buf, 0, v->len);
        v->buf = NULL;
        v->val = 0;
        v->len = 0;
        v->type = 0;
        v->refcount = 0;
        zone_free("value", v);
    }
}

void free_object(struct object * o) {
    free_value(o->id);
    free_value(o->name);
    zone_free("object", o);
}

struct value * find_value_int(size_t x) {
    size_t i;
    for (i = 0;i < MAX_COUNT; ++i) {
        if (!db[i].available) {
            if (db[i].ptr->id->val == x) {
                return db[i].ptr->id;
            }
        }
    }
    return NULL;
}

struct value * find_value_buf(char * buf, size_t len) {
    size_t i;
    size_t j;
    for (i = 0;i < MAX_COUNT; ++i) {
        if (!db[i].available) {
            if (db[i].ptr->name->len == len) {
                bool found = true;
                for (j = 0; j < len; ++j) {
                    if (db[i].ptr->name->buf[j] != buf[j]) {
                        found = false;
                    }
                }
                if (found) {
                    return db[i].ptr->name;
                }
            }
        }
    }
    return NULL;
}
void add_object() {
    size_t idx;
    size_t id;
    size_t len;
    struct object * obj;
    char * buf;
    printf("Index: ");
    idx = read_int();

    if ( idx >= MAX_COUNT || !db[idx].available) {
        puts("Invalid index");
        return;
    }

    printf("ID: ");
    id = read_int();
    printf("Name length: ");
    len = read_int();
    if (len >= 0x200) {
        puts("Name too long");
        return;
    }
    buf = zmalloc(len);
    printf("Name: ");
    read(0, buf, len);
    
    obj = zone_alloc("object");
    obj->id = find_value_int(id);
    if (!obj->id) {
        obj->id = zone_alloc("value");
        obj->id->type = INTEGER;
        obj->id->val = id;
        obj->id->refcount = 1;
        obj->id->buf = obj->id;
        obj->id->len = 0;
    }
    else {
        obj->id->refcount++;
    }
    obj->name = find_value_buf(buf, len);
    if (!obj->name) {
        obj->name = zone_alloc("value");
        obj->name->type = BUFFER;
        obj->name->len = len;
        obj->name->buf = buf;
        obj->name->refcount = 1;
    }
    else {
        zfree(buf, len);
        obj->name->refcount++;
    }

    db[idx].available = false;
    db[idx].ptr = obj;
}

void delete_object() {
    size_t idx;
    printf("Index: ");
    idx = read_int();

    if ( idx >= MAX_COUNT || db[idx].available) {
        puts("Invalid index");
        return;
    }
    free_object(db[idx].ptr);

    db[idx].available = true;
    db[idx].ptr = NULL;
}

void view_object() {
    size_t idx;
    printf("Index: ");
    idx = read_int();

    if ( idx >= MAX_COUNT || db[idx].available) {
        puts("Invalid index");
        return;
    }
    printf("ID: %llu\n", db[idx].ptr->id->val);
    printf("Name: ");
    write(1, db[idx].ptr->name->buf,  db[idx].ptr->name->len);
}

void copy_object() {
    size_t idx;
    size_t idx_copy;
    struct object * obj;
    printf("Index: ");
    idx = read_int();

    if ( idx >= MAX_COUNT || !db[idx].available) {
        puts("Invalid index");
        return;
    }

    printf("Copy from: ");
    idx_copy = read_int();

    if ( idx_copy >= MAX_COUNT || db[idx_copy].available) {
        puts("Invalid index");
        return;
    }

    obj = zone_alloc("object");
    obj->id     = db[idx_copy].ptr->id;
    obj->name   = db[idx_copy].ptr->name;

    db[idx].available = false;
    db[idx].ptr = obj;
}

void timeout() {
    puts("Timeout");
    exit(1);
}

void init() {
    size_t i;
    signal(0xe,&timeout);
    alarm(300);
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

    zone_create("value", sizeof (struct value));
    zone_create("object", sizeof (struct object));

    for (i = 0; i < MAX_COUNT; ++i) {
        db[i].available = true;
    }
}

void menu() {

    printf("\n");
    puts("------------------------");
    puts("1. Create object");
    puts("2. Delete object");
    puts("3. Copy object");
    puts("4. View object");
    puts("5. Exit");
    printf("> ");
}

int main(void) {
    init();
    puts("Zone allocator!");
    int choice;
    while (1) {
        menu();
        choice = read_int();
        switch (choice) {
            case 1:
                add_object();
                break;
            case 2:
                delete_object();
                break;
            case 3:
                copy_object();
                break;
            case 4:
                view_object();
                break;
            case 5:
                exit(0);
                break;
        }
    }

}