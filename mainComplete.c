#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct person {
    char name[20];
    int age;
};

int addition(int num1, int num2)
{
    int sum;
    sum = num1 + num2;
    return sum;
}

int subtraction(int num1, int num2)
{
    int sub;
    sub = num1 - num2;
    int add = addition(num1, num2);
    return sub;
}

char* memAlloc() {
    int size=10, i;

    char* my_array = (char*)malloc(size * sizeof(char));

    int len = strlen("0x90");
    for (i = 0; i < size - 1; i++) {
        strncpy(&my_array[i], "0x90", len);
    }
    strncpy(&my_array[size],"0xc3", len);
    char* array_ptr = &my_array[5];
    return array_ptr;
}

struct person persons[3];

int main()
{
    persons[0].age = 0;
    persons[1].age = -1;
    persons[2].age = 1000;
    strncpy(persons[0].name, "p1", 2);
    strncpy(persons[1].name, "p2" ,2);
    strncpy(persons[2].name, "p3", 2);
    
    int var1=15, var2=20, i=0;
    while (i< 10) {
        if (strncmp(persons[0].name,"p1",2)==0) {
            char* ptr = memAlloc();
        }
        i++;
    }
    switch (persons[1].age)
    {
    case 0:
        puts("Equal 0");
        break;
    case -1:
        puts("Equal -1");
        break;
    case 1000:
        puts("Equal 1000");
        break;
    default:
        puts("None of the above");
        break;
    }
    int resAdd = addition(var1, var2);
    int resSub = subtraction(var1, var2);
    return 0;
}