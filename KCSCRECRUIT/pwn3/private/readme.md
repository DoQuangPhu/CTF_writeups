# BSS OVERFLOW

This challenge was a basic bss overflow , you need to overwrite the struct of robot and call the `cat_flag` function . The tricky part was how to trigger the overflow bug and where is it.

If you read the source code you should had known that `long long sort[100]` was right on top of the struct robot , so you should look at `simple_sorted()` function.

Now take a look at `main()`:

```C
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
```


All this functions when they get called , they will use the same rbp and just sub rsp some what value to serve as the function variable. Now if you look at `menu()` and `simple_sorted()`

![image](https://github.com/DoQuangPhu/CTF_writeups/assets/93699926/44e32068-3d72-4b4c-af38-c95089563dcd)

`menu` and `simple_sorted` was really similar if you look at the variable. To be clear you can affect `n_sort_number` via menu's `i` .

```C
unsigned long n_sort_number;
    puts("How many numbers do you want to sort? ");
    scanf("%u", (unsigned int *)&n_sort_number);

    if (*(unsigned int*)&n_sort_number <= MAXSORTSIZE)
```

`n_sort_number` is 8byte but the function only check if lower 4 byte of it was smaller than MAXSORTSIZE, so if the higher 4 bytes of n_sort_number was have some junk value we should be able to trigger the overflow bug.
And we can do that via menu cause it let us scanf in the variable have size of 8byte . You may wonder if we input a choice bigger than the `cases` in main we should be jump in `default` right? but look at `int choice` it only have 4 byte in  
so if you input something like `0x100000005` choice will be just 5 and we will be able to call `simple_sort`, and just another trick to leak the exe address , if you input something like `+-*/` on scanf , the value at the address get scanf in wont be change.
So after you trigger the bug overflow and do scanf all the way to the robot struct just need to input `+` not change the value of the struct robot to leak the exe address and trigger the bug second time . This time you have the address of `cat_flag`,
just write it all over the robot and jump any cases in main . That it !!!!!
