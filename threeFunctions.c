#include<stdio.h>

int addition(int num1, int num2)
{
    int sum;
    sum = num1+num2;
    return sum;
}

int subtraction(int num1, int num2)
{
    int sub;
    sub = num1-num2;
    return sub;
}

int multiplication(int num1, int num2)
{
    int mul;
    mul = num1*num2;
    return mul;
}

float division(int num1, int num2)
{
    int div;
    div = num1/num2;
    return div;
}

int main()
{
    int var1, var2;
    printf("Enter number 1: ");
    scanf("%d",&var1);
    printf("Enter number 2: ");
    scanf("%d",&var2);
    int resAdd = addition(var1, var2);
    int resSub = subtraction(var1, var2);
    int resMul = multiplication(var1, var2);
    float resDiv = division(var1, var2);
    printf ("Addition: %d, Subtraction: %d, Multiplication: %d, Division: %f\n", resAdd, resSub, resMul, resDiv);
    return 0;
}