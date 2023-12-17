#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

char *review[5];
int size[5];
void writereview()
{
    unsigned int movie = 0;
    puts("\nHow many movie you want to write review(max is 5 though)");
    scanf("%d",&movie);
    if(movie <= 5) 
    {
        for(int i =0 ;i<movie;i++)
        {
            puts("how long is your review?");
            scanf("%d",&size[i]);
            review[i] = (char*) malloc(size[i]);
            puts("Give us some of your thought on the movie!!!");
            read(0,review[i],size[i] - 1);
        }

    }    
}
void removeReview()
{
    unsigned int i;
    puts("\nwhich review you want to remove??");
    scanf("%u",&i);
    if(i<5 && review[i])
    {
        free(review[i]);
    }
}


void ReviewTheReview()
{
    unsigned int i ;
    puts("Which review you want to look back!!!!");
    scanf("%u",&i);
    if(i<5)
    {
        puts(review[i]);
    }
}

void timeout() {
    puts("Timeout");
    exit(1);
}

void setup() {
    signal(0xe,&timeout);
    alarm(60);
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
}

int main()
{
    setup();
    int option;
    int n_guest;
    unsigned int lucky_index;
    unsigned long lucky[10];
    puts("\nWELCOME TO KCSC LETTERBOXD MINI PROGRAM!");
    while(1)
    {
        puts("\nwhat do you like to do?");
        scanf("%d",&option);
        switch(option)
        {
            case 1:
                writereview();
                break;
            case 2:
                ReviewTheReview();
                break ;
            case 3:
                removeReview();
                break;
            case 4:
                puts("\nTHIS IS JUST A MINI GAME , THE PRIZE IS NOTHING BUT THE CONTENT OF SOME FLAG\n");
                puts("\nHOW MANY NUMBER YOU WANT TO BET?(max is 10 tho)");
                scanf("%d",&n_guest);
                if(n_guest <= 10)
                {
                    for(int i = 0;i < n_guest;i++)
                    {
                        scanf("%ld",&lucky[lucky_index++]);
                    }
                }
                break;
            case 5:
                puts("bye bye");
                return 0;
            default:
                puts("\nnothing here!!");
        }

    }
}
