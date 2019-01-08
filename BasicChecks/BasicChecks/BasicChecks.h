#pragma once
#include <string>
#include <windef.h>
#include <iostream>
#include <psapi.h>
#include <iomanip>
#include <Windows.h>

#define c() std::cout <<"||"
#define l(len) std::cout<<"+";std::cout << std::left << std::setw(len-6) << std::setfill('-') << '-';std::cout<<"+"<<std::endl

using namespace std;

extern "C" __declspec(dllexport) void check();

