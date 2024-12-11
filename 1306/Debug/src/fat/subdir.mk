################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/fat/diskio.c \
../src/fat/ff.c \
../src/fat/ffsystem.c \
../src/fat/ffunicode.c 

OBJS += \
./src/fat/diskio.o \
./src/fat/ff.o \
./src/fat/ffsystem.o \
./src/fat/ffunicode.o 

C_DEPS += \
./src/fat/diskio.d \
./src/fat/ff.d \
./src/fat/ffsystem.d \
./src/fat/ffunicode.d 


# Each subdirectory must supply rules for building sources it contributes
src/fat/%.o: ../src/fat/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: MicroBlaze gcc compiler'
	mb-gcc -Wall -O0 -g3 -c -fmessage-length=0 -MT"$@" -I../../1306_bsp/u_nhc_amba_core_cpu_subsystem_u_cpu_subsystem_i_microblaze_1/include -mlittle-endian -mxl-barrel-shift -mxl-pattern-compare -mno-xl-soft-div -mcpu=v11.0 -mno-xl-soft-mul -mxl-multiply-high -mhard-float -mxl-float-convert -mxl-float-sqrt -Wl,--no-relax -ffunction-sections -fdata-sections -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


