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
    return sub;
}

/*
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
*/

/*
int conditional_jump_with_constant_condition(int var1, int var2)
{
    int resAdd = addition(var1, var2);
    puts("Conditional jump with constant condition");
    __asm {
        push eax
        xor eax, eax
        jz $ + 7
        __emit 0xe8
        pop eax
    }
    int resSub = subtraction(resAdd, var2);
    return resAdd;
}
*/

int impossible_disassembly(int var1, int var2){
    int resAdd = addition(var1, var2);
    puts("Impossible disassembly");
    __asm {
        __emit 0xeb
        __emit 0xff
        __emit 0xc0
        __emit 0x48
    }
    int resSub = subtraction(resAdd, var2);
    return resAdd;
}

int incrementAge(int age) {
    //int ageIncr = conditional_jumps_with_same_target(age, 10);
    //int ageIncr = conditional_jump_with_constant_condition(age, 10);
    int ageIncr = impossible_disassembly(age, 10);
    return ageIncr;
}

char* memAlloc() {
    int size = 10, i;

    char* my_array = (char*)malloc(size * sizeof(char));

    int len = strlen("0x90");
    for (i = 0; i < size - 1; i++) {
        strcpy_s(&my_array[i], len+1, "0x90");
    }
    strcpy_s(&my_array[size], len+1, "0xc3");
    char* array_ptr = &my_array[5];
    return array_ptr;
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

    int var1 = 15, var2 = 20;
    while (persons[0].age < 10) {
        persons[0].age = incrementAge(persons[0].age);
        if (strncmp(persons[0].name, "p1", 2) == 0) {
            char* ptr = memAlloc();
        }
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
    //conditional_jumps_with_same_target(var1, var2);
    //conditional_jump_with_constant_condition(var1, var2);
    impossible_disassembly(var1,var2);
    return 0;
}