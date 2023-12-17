#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdbool.h>

int menu()
{

    unsigned long i = 1;
    printf("%ld.addition\n",i++);
    printf("%ld.subtraction\n",i++);
    printf("%ld.division\n",i++);
    printf("%ld.multiplication\n"),i++;
    printf("%ld.simple sort\n",i++);
    printf("Enter your choice: \n");
    scanf("%ld",&i);
    return i;
}

struct Robot{

    void (*speak)();
    void (*say_hello)();
    void (*cat_flag)() ;
    void (*cook)();
    void (*emergency)();
    void (*addition)();
    void (*subtraction)();
    void (*division)();
    void (*multiplication)();
    void (*simple_sorted)() ;    
};

unsigned long i,j;
unsigned long temp;
long long sort[100]; 
#define MAXSORTSIZE 100
void simple_sorted()
{   
    unsigned long n_sort_number;
    puts("How many numbers do you want to sort? ");
    scanf("%u", (unsigned int *)&n_sort_number);

    if (*(unsigned int*)&n_sort_number <= MAXSORTSIZE) {
        for (i = 0; i < n_sort_number; i++) {
            printf("Enter the element: ");
            scanf("%lld", &sort[i]);
            if(sort[i] < 0)
            {
                puts("Unable to process negative for now!!!");
                n_sort_number = i;
                break;
            }
        }

        // Bubble sort algorithm
        for (i = 0; i < n_sort_number - 1; i++) {
            for (j = 0; j < n_sort_number - i - 1; j++) {
                if (sort[j] > sort[j + 1]) {
                    // Swap elements
                    temp = sort[j];
                    sort[j] = sort[j + 1];
                    sort[j + 1] = temp;
                }
            }
        }

        printf("\nSorted array: ");
        for (i = 0; i < n_sort_number; i++) {
            printf("%llu\n", sort[i]);
        }
        printf("\n");
    } else {
        printf("Number of elements exceeds the maximum size.\n");
    }
}


void addition()
{
    long long first;
    long long second;
    long long result;
    puts("Enter first number:");
    scanf("%lld",&first);
    puts("Enter second number:");
    scanf("%lld",&second);
    puts("simple addition : ");
    result = first + second ;
    printf("%lld\n",result);
}


void speak()
{
    /*still under construction*/
    puts("ill under construction");

}

void say_hello()
{
    /*still under construction*/
    puts("llo there!");
}

void cat_flag()
{
    system("/bin/sh");
}

void cook()
{
    puts("ill in constrution tho");
}

void emergency()
{
    puts("ill in constrution tho");
}

void subtraction()
{
    long long first;
    long long second;
    long long result;
    puts("Enter first number:");
    scanf("%lld",&first);
    puts("Enter second number:");
    scanf("%lld",&second);
    puts("simple subtraction : ");
    result = first - second ;
    printf("%lld\n",result);
}


void division()
{
    long long first;
    long long second;
    long long result;
    puts("Enter first number:");
    scanf("%lld",&first);
    puts("Enter second number:");
    scanf("%lld",&second);
    puts("simple division : ");
    result = first / second ;
    printf("%lld\n",result);
}


void multiplication()
{
    long long first;
    long long second;
    long long result;
    puts("Enter first number:");
    scanf("%lld",&first);
    puts("Enter second number:");
    scanf("%lld",&second);
    puts("simple division : ");
    result = first * second ;
    printf("%lld\n",result);
}


void InitRobot(struct Robot *robot) {
    robot->speak = speak;
    robot->say_hello = say_hello;
    robot->cat_flag = cat_flag;
    robot->cook = cook;
    robot->emergency = emergency;
    robot->addition = addition; 
    robot->subtraction = subtraction;
    robot->division = division;
    robot->multiplication = multiplication;
    robot->simple_sorted = simple_sorted;
}
struct Robot robot;

void timeout() {
    puts("meout");
    exit(1);
}

void setup() {
    signal(0xe,&timeout);
    alarm(60);
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
}


int main() {
    setup();
    InitRobot(&robot);
    int choice;
    puts("SIMPLE CALCULATOR WHICH HELP YOU DO SIMPLE MATH,SIMPLE SORT, AND EVEN GETTING A SHELL!!!");
    while(1)
    {
        choice = menu();
        switch (choice)
        {   
            case 1:
                robot.addition();
                break ;
            case 2: 
                robot.subtraction();
                break ;
            case 3:
                robot.division();
                break;
            case 4:
                robot.multiplication();
                break;
            case 5:
                robot.simple_sorted();
                break;
            case 6:
                return 0;
            default:
                puts("nothing here!");
                break;
        }
    }
}