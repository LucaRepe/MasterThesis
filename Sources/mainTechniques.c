#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

struct person {
    char name[20];
    int age;
};


int addition(int num1, int num2) {
    int sum;
    sum = num1 + num2;
    return sum;
}


int subtraction(int num1, int num2) {
    int sub;
    sub = num1 - num2;
    return sub;
}


/*
int conditional_jumps_with_same_target(int var1, int var2) {
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
int conditional_jump_with_constant_condition(int var1, int var2) {
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

/*
int impossible_disassembly(int var1, int var2) {
    int resAdd = addition(var1, var2);
    puts("Impossible disassembly");
    __asm {
        __emit 0xeb
        __emit 0xff
        __emit 0xc0
        __emit 0x48
    }
    __asm {
        __emit 0x66
        __emit 0xb8
        __emit 0xeb
        __emit 0x05
        __emit 0x31
        __emit 0xc0
        __emit 0x74
        __emit 0xf9
        __emit 0xe8
        __emit 0x58
        __emit 0xc3
        __emit 0x90
        __emit 0x90

    }
    int resSub = subtraction(resAdd, var2);
    return resAdd;
}
*/

/*
int register_reassignment(int var1, int var2) {
    int resAdd = addition(var1, var2);
    puts("Register reassignment");
    __asm {
        mov eax, 0
        mov ebx, 0
        add eax, 1
        add ebx, 2
        mov ebx, eax
        mov eax, ebx
        add eax, 1
        add ebx, 2
        ret
    }
    int resSub = subtraction(resAdd, var2);
    return resAdd;
}
*/

/*
int disassembly_desynchronization(int var1, int var2) {
    int resAdd = addition(var1, var2);
    puts("Disassembly desynchronization");
    __asm {
        mov eax, 0x12345678
        add eax, 0x00000004
    }

    __asm {
        nop
        nop
        nop
        nop
    }

    __asm {
        mov ebx, 0x87654321
        sub ebx, 0x00000004
    }
    int resSub = subtraction(resAdd, var2);
    return resAdd;
}
*/

/*
int dynamically_computed_target_address(int var1, int var2) {
    int resAdd = addition(var1, var2);
    puts("Dynamically computed target address");

    char* target = (char*)malloc(8);
    *(unsigned long long*)target = (unsigned long long)dynamically_computed_target_address + 0x00000004;

    __asm { 
        mov eax, target
        call eax
    }
    int resSub = subtraction(resAdd, var2);
    return resAdd;
}
*/


void hidden_fun() {
    puts("Hi I'm an hidden function");
}


int return_pointer_abuse(int var1, int var2, DWORD fun) {
    int resAdd = addition(var1, var2);
    puts("Return pointer abuse");

    __asm {
        call $ + 5
        add dword ptr[esp], 5
        retn

        mov eax, dword ptr[fun]
        add eax, 10
        call eax
    }

    int resSub = subtraction(resAdd, var2);
    return resAdd;
}


/*
DWORD handle_exception(EXCEPTION_POINTERS* ep) {
    return ep->ExceptionRecord->ExceptionCode;
}

int structured_exception_handler_misuse(int var1, int var2) {
    int resAdd = addition(var1, var2);
    puts("Structured exception handler misuse");

    LPVOID fn = &handle_exception;
    __asm {
        mov eax, dword ptr fs:[0]
        mov eax, dword ptr[eax + 0x04]
        push fn
        push dword ptr[eax]
        mov dword ptr[eax], esp
    }

    __try {
        *(int*)0 = 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        __asm {
            mov eax, dword ptr fs:[0]
            mov eax, dword ptr[eax + 0x04]
            mov esp, dword ptr[eax]
            pop dword ptr[eax]
        }
    }

    int resSub = subtraction(resAdd, var2);
    return resAdd;
}
*/

int incrementAge(int age) {
    //int ageIncr = conditional_jumps_with_same_target(age, 10);
    //int ageIncr = conditional_jump_with_constant_condition(age, 10);
    //int ageIncr = impossible_disassembly(age, 10);
    //int ageIncr = register_reassignment(age, 10);
    //int ageIncr = disassembly_desynchronization(age, 10);
    //int ageIncr = dynamically_computed_target_address(age, 10);
    int ageIncr = return_pointer_abuse(age, 10, (DWORD)hidden_fun - 10);
    //int ageIncr = structured_exception_handler_misuse(age, 10);
    return ageIncr;
}


char* memAlloc() {
    int size = 10, i;
    char* my_array = (char*)malloc(size * sizeof(char));
    int len = strlen("0x90");
    for (i = 0; i < size - 1; i++) {
        strcpy_s(&my_array[i], len + 1, "0x90");
    }
    strcpy_s(&my_array[size], len + 1, "0xc3");
    char* array_ptr = &my_array[5];
    return array_ptr;
}


struct person persons[3];

int main() {
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

    switch (persons[1].age) {
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
    //impossible_disassembly(var1, var2);
    //register_reassignment(var1, var2);
    //disassembly_desynchronization(var1, var2);
    //dynamically_computed_target_address(var1, var2);
    DWORD func_ptr = (DWORD)hidden_fun - 10;
    return_pointer_abuse(var1, var2, func_ptr);
    //structured_exception_handler_misuse(var1, var2);
    return 0;
}