cmake_minimum_required(VERSION 3.6)
project(ELF_Loader)

set(CMAKE_C_STANDARD 99)

set(SOURCE_FILES main.c elf.c elf.h)
add_executable(ELF_Loader ${SOURCE_FILES})