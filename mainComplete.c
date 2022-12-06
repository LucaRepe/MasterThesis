#include<stdio.h>
#include<string.h>

struct person {
    char name[20];
    int age;
};

int incrementAge(int age) {
    int ageIncr = conditional_jumps_with_same_target(age, 10);
    return ageIncr;
}

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
    return sub;
}

int conditional_jumps_with_same_target(int var1, int var2)
{
    int resAdd = addition(var1, var2);
    puts("Conditional jumps with same target");
    __asm {
        jz $ + 13
        jnz $ + 7
        __emit 0xe8
    }
    int resSub = subtraction(resAdd, var2);
    return resAdd;
}

void memAlloc() {
    int size=10, i, * my_array;

    my_array = (char*)malloc(size * sizeof(int));

    for (i = 0; i < size; i++) {
        strcpy_s(&my_array[i], sizeof(&my_array[i]), 4, "0x90");
    }
}

struct person persons[3];

int main()
{
    persons[0].age = 0;
    persons[1].age = -1;
    persons[2].age = 1000;
    strncpy_s(persons[0].name, sizeof(persons[0].name), "p1", 2);
    strncpy_s(persons[1].name, sizeof(persons[1].name), "p2", 2);
    strncpy_s(persons[2].name, sizeof(persons[2].name), "p3", 2);
    
    int var1=15, var2=20;
    while (persons[0].age < 10) {
        persons[0].age = incrementAge(persons[0].age);
        if (persons[0].name == "p1") {
            memAlloc();
        }
    }
    int resAdd = addition(var1, var2);
    int resSub = subtraction(var1, var2);
    conditional_jumps_with_same_target(var1, var2);
    return 0;
}