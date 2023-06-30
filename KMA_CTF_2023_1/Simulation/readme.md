# Review source code:

```C
#define CONSTANT    0
#define REGISTER    1
#define MEM         2
#define MAX_COUNT 0x100

enum COMMAND_TYPE {
    ADD,
    SUBTRACT,
    MULTIPLY,
    DIVIDE,
    STORE,
    LOAD
};

struct arg {
    size_t type;
    size_t val;
};

struct command {
    size_t func;
    struct arg arg[3];
};

struct node {
    uint32_t error_handler;
    uint32_t cur_cmd;
    uint32_t nb_cmd;
    uint32_t next_node;
    int (*error_callback)(struct node *, uint32_t, bool);
    struct command cmd[0];
};


uint32_t node_head;
struct node * node_list[MAX_COUNT];
uint32_t ip;
uint64_t re[5];

char * mem;
size_t mem_size;
```
Ta thấy chương trình khai báo Struct node với các biến như sau :
```C
uint32_t error_handler; 4 bytes
uint32_t cur_cmd;       4 bytes
uint32_t nb_cmd;        4 bytes
uint32_t next_node;     4 bytes
int (*error_callback)(struct node *, uint32_t, bool); ptr chỉ đến các 1 trong 3 func handler
struct command cmd[0];  struct command 
```

Struct command được khai báo :
```C
struct command {
    size_t func;       8 bytes
    struct arg arg[3]; strcut arg 
};
```

Struct arg được khai báo:
```C
#define CONSTANT    0
#define REGISTER    1
#define MEM         2

struct arg {
    size_t type; type sẽ có thể nhận 1 trong 3 giá trị CONSTANT,REGISTER,MEM.
    size_t val;  
};
```
Nếu arg.type == CONSTANT thì arg.val có thể bằng giá trị mà chúng ta muôn (VD:0xdeadbeef)

Nếu arg.type == REGISTER thì arg.val sẽ là index trỏ đến giá trị ở vị trí của vùng nhớ re dược khai báo trước đó `uint64_t re[5];`

Nếu arg.type == MEM thì arg.val sẽ là index trỏ đến giá trị ở vị trí của vùng nhớ mem dược khai báo trước đó `char * mem;
size_t mem_size;`

Check qua hàm main ta có thể thấy được vùng nhớ mem sẽ được khai báo là vùng nhớ heap với size sẽ tương đương với mem_size . Và mem_size thì sẽ được update sau khi chương trình chạy hàm simulate()
```C
case 2:
    printf("Where to start? ");
    node_head = read_int();
    if (node_head == 0 || node_head > MAX_COUNT) {
        puts("Invalid start");
        break;
    }
    simulate();
    mem = calloc(mem_size, 1);
    if (!mem) {
        puts("Out of memory");
        exit(1);
    }
    run();
    free(mem);
    mem = NULL;
    mem_size = 0;
    cleanup();
    break;	
```
Kiểm tra hàm simulate() và hàm run() ta thấy hai hàm này gần gần same same nhau :

Hàm simulate()
```C
void simulate() {
    struct node * cur_node;
    size_t i;
    ip = node_head;
    memset(re, 0, sizeof re);
    memset(mem, 0, mem_size);
    uint64_t tmp;
    uint32_t cycle = 0;
    uint32_t status_code;
    while (cycle <= 0x5000) {
        cur_node = node_list[ip];
        if (!cur_node) {
            break;
        }
        if (cur_node->cur_cmd >= cur_node->nb_cmd) {
            if (cur_node->next_node) {
                ip = cur_node->next_node;
                cur_node = node_list[ip];
            }
            else {
                break;
            }
        }
        cycle++;
        switch (cur_node->cmd[cur_node->cur_cmd].func) {
            case ADD:
                tmp = get_val_safe(&cur_node->cmd[cur_node->cur_cmd].arg[0]) + get_val_safe(&cur_node->cmd[cur_node->cur_cmd].arg[1]);
                store_val_safe(&cur_node->cmd[cur_node->cur_cmd].arg[2], tmp);
                cur_node->cur_cmd++;
                break;
            case SUBTRACT:
                tmp = get_val_safe(&cur_node->cmd[cur_node->cur_cmd].arg[0]) - get_val_safe(&cur_node->cmd[cur_node->cur_cmd].arg[1]);
                store_val_safe(&cur_node->cmd[cur_node->cur_cmd].arg[2], tmp);
                cur_node->cur_cmd++;
                break;
            case MULTIPLY:
                tmp = get_val_safe(&cur_node->cmd[cur_node->cur_cmd].arg[0]) * get_val_safe(&cur_node->cmd[cur_node->cur_cmd].arg[1]);
                store_val_safe(&cur_node->cmd[cur_node->cur_cmd].arg[2], tmp);
                cur_node->cur_cmd++;
                break;
            case DIVIDE:
                if (get_val_safe(&cur_node->cmd[cur_node->cur_cmd].arg[1]) == 0) {
                    status_code = resolve_error(cur_node, ip, 0);
                    if (status_code == 0) {
                        return;
                    }
                    if (status_code == 1) {
                        break;
                    }
                    if (status_code == 2) {
                        ip = cur_node->error_handler;
                        continue;
                    }
                }
                tmp = get_val_safe(&cur_node->cmd[cur_node->cur_cmd].arg[0]) / get_val_safe(&cur_node->cmd[cur_node->cur_cmd].arg[1]);
                store_val_safe(&cur_node->cmd[cur_node->cur_cmd].arg[2], tmp);
                cur_node->cur_cmd++;
                break;
            case LOAD:
                if (cur_node->cmd[cur_node->cur_cmd].arg[0].type != MEM) {
                    status_code = resolve_error(cur_node, ip, 0);
                    if (status_code == 0) {
                        return;
                    }
                    if (status_code == 1) {
                        break;
                    }
                    if (status_code == 2) {
                        ip = cur_node->error_handler;
                        continue;
                    }
                }
                tmp = get_val_safe(&cur_node->cmd[cur_node->cur_cmd].arg[0]);
                store_val_safe(&cur_node->cmd[cur_node->cur_cmd].arg[1], tmp);
                cur_node->cur_cmd++;
                break;
            case STORE:
                if (cur_node->cmd[cur_node->cur_cmd].arg[0].type != MEM) {
                    status_code = resolve_error(cur_node, ip, 0);
                    if (status_code == 0) {
                        return;
                    }
                    if (status_code == 1) {
                        break;
                    }
                    if (status_code == 2) {
                        ip = cur_node->error_handler;
                        continue;
                    }
                }
                store_val_safe(&cur_node->cmd[cur_node->cur_cmd].arg[0], get_val_safe(&cur_node->cmd[cur_node->cur_cmd].arg[1]));
                cur_node->cur_cmd++;
                break;
        }        
    }
    for (i = 0; i < MAX_COUNT; ++i) {
        if (node_list[i]) {
            node_list[i]->cur_cmd = 0;
        }
    }
}
```
Hàm Simulate sẽ chạy vòng While loop cho đến khi cur_node == NULL, hoặc cur_node->next_node=0 .

Đối với mỗi node chương trình sẽ chạy case tương ứng với các func như sau :
```C
enum COMMAND_TYPE {
    ADD,
    SUBTRACT,
    MULTIPLY,
    DIVIDE,
    STORE,
    LOAD
};
```

Ta thấy đối với mỗi case : chương trình sẽ gọi hàm get_val_safe(struct arg * arg) hoặc store_val_safe(struct arg * arg, uint64_t val).

```C
uint64_t get_val_safe(struct arg * arg) {
    switch (arg->type) {
        case CONSTANT:
            return arg->val;
        case REGISTER:
            return re[arg->val];
        case MEM:
            if (arg->val + 8 > mem_size) {
                mem_size = arg->val + 8;
                return 0;
            }
            return 0;
    }
}

void store_val_safe(struct arg * arg, uint64_t val) {
    switch (arg->type) {
        case CONSTANT:
            return;
        case REGISTER:
            return re[arg->val] = val;
        case MEM:
            if (arg->val + 8 > mem_size) {
                mem_size = arg->val + 8;
                return;
            }
    }
}
```
đối với mỗi case MEM, hàm get_val_safe hoặc store_val_safe sẽ check
```C
if (arg->val + 8 > mem_size) {
                mem_size = arg->val + 8;
                return;
            }
```
Mà arg.type == MEM thì arg.val sẽ là index trỏ đến giá trị ở vị trí của vùng nhớ mem được khai báo trước đó char * mem; size_t mem_size;

Vậy hàm simulate()  như ta có thể thấy sẽ đơn giản là check và update mem_size. 

Hàm run() được thiết kế như sau :
```C
void run() {
    struct node * cur_node;
    ip = node_head;
    memset(re, 0, sizeof re);
    memset(mem, 0, mem_size);
    uint64_t tmp;
    uint32_t cycle = 0;
    uint32_t status_code;
    while (cycle <= 0x5000) {
        cur_node = node_list[ip];
        if (!cur_node) {
            break;
        }
        if (cur_node->cur_cmd >= cur_node->nb_cmd) {
            if (cur_node->next_node) {
                ip = cur_node->next_node;
                cur_node = node_list[ip];
            }
            else {
                break;
            }
        }
        cycle++;
        switch (cur_node->cmd[cur_node->cur_cmd].func) {
            case ADD:
                tmp = get_val(&cur_node->cmd[cur_node->cur_cmd].arg[0]) + get_val(&cur_node->cmd[cur_node->cur_cmd].arg[1]);
                store_val(&cur_node->cmd[cur_node->cur_cmd].arg[2], tmp);
                cur_node->cur_cmd++;
                break;
            case SUBTRACT:
                tmp = get_val(&cur_node->cmd[cur_node->cur_cmd].arg[0]) - get_val(&cur_node->cmd[cur_node->cur_cmd].arg[1]);
                store_val(&cur_node->cmd[cur_node->cur_cmd].arg[2], tmp);
                cur_node->cur_cmd++;
                break;
            case MULTIPLY:
                tmp = get_val(&cur_node->cmd[cur_node->cur_cmd].arg[0]) * get_val(&cur_node->cmd[cur_node->cur_cmd].arg[1]);
                store_val(&cur_node->cmd[cur_node->cur_cmd].arg[2], tmp);
                cur_node->cur_cmd++;
                break;
            case DIVIDE:
                if (get_val(&cur_node->cmd[cur_node->cur_cmd].arg[1]) == 0) {
                    status_code = resolve_error(cur_node, ip, 1);
                    if (status_code == 0) {
                        goto output;
                    }
                    if (status_code == 1) {
                        break;
                    }
                    if (status_code == 2) {
                        ip = cur_node->error_handler;
                        continue;
                    }
                }
                tmp = get_val(&cur_node->cmd[cur_node->cur_cmd].arg[0]) / get_val(&cur_node->cmd[cur_node->cur_cmd].arg[1]);
                store_val(&cur_node->cmd[cur_node->cur_cmd].arg[2], tmp);
                cur_node->cur_cmd++;
                break;
            case LOAD:
                if (cur_node->cmd[cur_node->cur_cmd].arg[0].type != MEM) {
                    status_code = resolve_error(cur_node, ip, 1);
                    if (status_code == 0) {
                        goto output;
                    }
                    if (status_code == 1) {
                        break;
                    }
                    if (status_code == 2) {
                        ip = cur_node->error_handler;
                        continue;
                    }
                }
                tmp = get_val(&cur_node->cmd[cur_node->cur_cmd].arg[0]);
                store_val(&cur_node->cmd[cur_node->cur_cmd].arg[1], tmp);
                cur_node->cur_cmd++;
                break;
            case STORE:
                if (cur_node->cmd[cur_node->cur_cmd].arg[0].type != MEM) {
                    status_code = resolve_error(cur_node, ip, 1);
                    if (status_code == 0) {
                        goto output;
                    }
                    if (status_code == 1) {
                        break;
                    }
                    if (status_code == 2) {
                        ip = cur_node->error_handler;
                        continue;
                    }
                }
                store_val(&cur_node->cmd[cur_node->cur_cmd].arg[0], get_val(&cur_node->cmd[cur_node->cur_cmd].arg[1]));
                cur_node->cur_cmd++;
                break;

        }

        
    }
output:
    puts("Finish running");
    printf("IP: %u\n", ip);
}
```
Hàm run() tương tự như hàm Simulate() nhưng thay vì gọi hàm get_val_safe hoặc store_val_safe thì nó sẽ gọi hàm get_val hoặc store_val

```C
uint64_t get_val(struct arg * arg) {
    switch (arg->type) {
        case CONSTANT:
            return arg->val;
        case REGISTER:
            return re[arg->val];
        case MEM:
            return *(uint64_t *)(&mem[arg->val]);
    }
}

void store_val(struct arg * arg, uint64_t val) {
    switch (arg->type) {
        case CONSTANT:
            return;
        case REGISTER:
            re[arg->val] = val;
            return;
        case MEM:
            *(uint64_t *)(&mem[arg->val]) = val;// out of bound
            return;
    }
}
```

Hàm get_val() và store_val() sẽ lưu giá trị vào địa chỉ mem[index] mà không có bất cứ hàm nào để check xem liệu index đó có vượt ra khỏi vùng nhớ mem đã được malloc trước đó .
  
#Phân tích lỗi và hướng khai thác

hàm simulate()
```C
            case DIVIDE:
                if (get_val_safe(&cur_node->cmd[cur_node->cur_cmd].arg[1]) == 0) {
                    status_code = resolve_error(cur_node, ip, 0);
                    if (status_code == 0) {
                        return;
                    }
                    if (status_code == 1) {
                        break;
                    }
                    if (status_code == 2) {
                        ip = cur_node->error_handler;
                        continue;
                    }
                }
                tmp = get_val_safe(&cur_node->cmd[cur_node->cur_cmd].arg[0]) / get_val_safe(&cur_node->cmd[cur_node->cur_cmd].arg[1]);
                store_val_safe(&cur_node->cmd[cur_node->cur_cmd].arg[2], tmp);
                cur_node->cur_cmd++;
                break;
            case LOAD:
                if (cur_node->cmd[cur_node->cur_cmd].arg[0].type != MEM) {
                    status_code = resolve_error(cur_node, ip, 0);
                    if (status_code == 0) {
                        return;
                    }
                    if (status_code == 1) {
                        break;
                    }
                    if (status_code == 2) {
                        ip = cur_node->error_handler;
                        continue;
                    }
                }
                tmp = get_val_safe(&cur_node->cmd[cur_node->cur_cmd].arg[0]);
                store_val_safe(&cur_node->cmd[cur_node->cur_cmd].arg[1], tmp);
                cur_node->cur_cmd++;
                break;
            case STORE:
                if (cur_node->cmd[cur_node->cur_cmd].arg[0].type != MEM) {
                    status_code = resolve_error(cur_node, ip, 0);
                    if (status_code == 0) {
                        return;
                    }
                    if (status_code == 1) {
                        break;
                    }
                    if (status_code == 2) {
                        ip = cur_node->error_handler;
                        continue;
                    }
                }
                store_val_safe(&cur_node->cmd[cur_node->cur_cmd].arg[0], get_val_safe(&cur_node->cmd[cur_node->cur_cmd].arg[1]));
                cur_node->cur_cmd++;
                break;
```

Hàm run()
```C
case DIVIDE:
                if (get_val(&cur_node->cmd[cur_node->cur_cmd].arg[1]) == 0) {
                    status_code = resolve_error(cur_node, ip, 1);
                    if (status_code == 0) {
                        goto output;
                    }
                    if (status_code == 1) {
                        break;
                    }
                    if (status_code == 2) {
                        ip = cur_node->error_handler;
                        continue;
                    }
                }
                tmp = get_val(&cur_node->cmd[cur_node->cur_cmd].arg[0]) / get_val(&cur_node->cmd[cur_node->cur_cmd].arg[1]);
                store_val(&cur_node->cmd[cur_node->cur_cmd].arg[2], tmp);
                cur_node->cur_cmd++;
                break;
            case LOAD:
                if (cur_node->cmd[cur_node->cur_cmd].arg[0].type != MEM) {
                    status_code = resolve_error(cur_node, ip, 1);
                    if (status_code == 0) {
                        goto output;
                    }
                    if (status_code == 1) {
                        break;
                    }
                    if (status_code == 2) {
                        ip = cur_node->error_handler;
                        continue;
                    }
                }
                tmp = get_val(&cur_node->cmd[cur_node->cur_cmd].arg[0]);
                store_val(&cur_node->cmd[cur_node->cur_cmd].arg[1], tmp);
                cur_node->cur_cmd++;
                break;
            case STORE:
                if (cur_node->cmd[cur_node->cur_cmd].arg[0].type != MEM) {
                    status_code = resolve_error(cur_node, ip, 1);
                    if (status_code == 0) {
                        goto output;
                    }
                    if (status_code == 1) {
                        break;
                    }
                    if (status_code == 2) {
                        ip = cur_node->error_handler;
                        continue;
                    }
                }
                store_val(&cur_node->cmd[cur_node->cur_cmd].arg[0], get_val(&cur_node->cmd[cur_node->cur_cmd].arg[1]));
                cur_node->cur_cmd++;
                break;

        }
```

ta biết rằng hàm simulate() chỉ check và update mem_size nhưng không hề update memory,re.

Còn hàm run() sẽ thực hiện từng node và sẽ thật sự sẽ lưu giá trị vô re hoặc mem.

VD: nếu như ở hàm nếu ta tạo hai node là với hai func là ADD và DIVIDE

node ADD ta sẽ tạo ADD CONSTANT1,CONSTANT2,MEM[0]

node DIVIDE ta sẽ tạo node DIVIDE CONSTANT1,MEM[0],MEM[0x50]
)
ở hàm simulate() chương trình sẽ thực hiện node 1 (ADD CONSTANT,CONSTANT,MEM[0x18]) chương trình sẽ thực hiện đoạn code tương đương như sau :
```C
tmp = get_val_safe(CONSTANT1) + get_val_safe(CONSTANT2);
store_val_safe(&cur_node->cmd[cur_node->cur_cmd].arg[2], tmp);
cur_node->cur_cmd++;
break;
``` 

hàm get_val_safe và store_val_safe sẽ chỉ check bound và update mem_size . Nhưng đến khi thực hiện node(DIVIDE CONSTANT1,MEM[0],MEM[0x50]) thì case DIVIDE sẽ nhảy vào nhánh `if` và break vì get_val_safe(&cur_node->cmd[cur_node->cur_cmd].arg[1])== MEM[0] ==0:

```C
case DIVIDE:
                if (get_val_safe(&cur_node->cmd[cur_node->cur_cmd].arg[1]) == 0) {
                    status_code = resolve_error(cur_node, ip, 0);
                    if (status_code == 0) {
                        return;
                    }
                    if (status_code == 1) {
                        break;
                    }
                    if (status_code == 2) {
                        ip = cur_node->error_handler;
                        continue;
                    }
                }
                tmp = get_val_safe(&cur_node->cmd[cur_node->cur_cmd].arg[0]) / get_val_safe(&cur_node->cmd[cur_node->cur_cmd].arg[1]);
                store_val_safe(&cur_node->cmd[cur_node->cur_cmd].arg[2], tmp);
                cur_node->cur_cmd++;
                break;

```

và nó sẽ không thực hiện hàm 
```C
tmp = get_val_safe(&cur_node->cmd[cur_node->cur_cmd].arg[0]) / get_val_safe(&cur_node->cmd[cur_node->cur_cmd].arg[1]);
store_val_safe(&cur_node->cmd[cur_node->cur_cmd].arg[2], tmp);
cur_node->cur_cmd++;
break;
```
trong khi hàm store_val_safe() đáng nhẽ check MEM[0x50]-địa chỉ mem mà ta muốn lưu và sẽ update mem_size thành 0x58 .

Và khi đến hàm run()chương trình sẽ thực hiện node(ADD CONSTANT1,CONSTANT2,MEM[0]) tức nó sẽ lấy CONSTANT1+CONSTANT2 và lưu vô MEM[0]

vậy đến khi thực hiện node(DIVIDE CONSTANT1,MEM[0],MEM[0x50])  thì MEM[0] đã được update thành CONSTANT1+CONSTANT2 và nó sẽ không nhảy vô nhánh `if`:
```C
case DIVIDE:
                if (get_val(&cur_node->cmd[cur_node->cur_cmd].arg[1]) == 0) {
                    status_code = resolve_error(cur_node, ip, 1);
                    if (status_code == 0) {
                        goto output;
                    }
                    if (status_code == 1) {
                        break;
                    }
                    if (status_code == 2) {
                        ip = cur_node->error_handler;
                        continue;
                    }
                }
tmp = get_val(&cur_node->cmd[cur_node->cur_cmd].arg[0]) / get_val(&cur_node->cmd[cur_node->cur_cmd].arg[1]);
store_val(&cur_node->cmd[cur_node->cur_cmd].arg[2], tmp);
cur_node->cur_cmd++;
break;
```

mà sẽ nhảy vô 
```C
tmp = get_val(&cur_node->cmd[cur_node->cur_cmd].arg[0]) / get_val(&cur_node->cmd[cur_node->cur_cmd].arg[1]);
store_val(&cur_node->cmd[cur_node->cur_cmd].arg[2], tmp);
cur_node->cur_cmd++;
break;
```

mà như đã phân tích ở trên thì hàm store_val() không hề có bất kỳ check nào xem liệu địa chỉ ta muốn lưu vô có vượt quá địa chỉ mem đã được malloc trước đó không .==> out of bound 

