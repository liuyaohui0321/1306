################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
LD_SRCS += \
../src/lscript.ld 

C_SRCS += \
../src/FIFO.c \
../src/alloc.c \
../src/cmd.c \
../src/main.c \
../src/mem_test.c \
../src/nhc_amba.c \
../src/platform.c \
../src/ring_buffer.c \
../src/simple_dma.c \
../src/stm32uart_intr.c \
../src/xllfifo_polling_example.c \
../src/xspi_flash.c 

OBJS += \
./src/FIFO.o \
./src/alloc.o \
./src/cmd.o \
./src/main.o \
./src/mem_test.o \
./src/nhc_amba.o \
./src/platform.o \
./src/ring_buffer.o \
./src/simple_dma.o \
./src/stm32uart_intr.o \
./src/xllfifo_polling_example.o \
./src/xspi_flash.o 

C_DEPS += \
./src/FIFO.d \
./src/alloc.d \
./src/cmd.d \
./src/main.d \
./src/mem_test.d \
./src/nhc_amba.d \
./src/platform.d \
./src/ring_buffer.d \
./src/simple_dma.d \
./src/stm32uart_intr.d \
./src/xllfifo_polling_example.d \
./src/xspi_flash.d 


# Each subdirectory must supply rules for building sources it contributes
src/%.o: ../src/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: MicroBlaze gcc compiler'
	mb-gcc -Wall -O0 -g3 -c -fmessage-length=0 -MT"$@" -I../../1306_bsp/u_nhc_amba_core_cpu_subsystem_u_cpu_subsystem_i_microblaze_1/include -mlittle-endian -mxl-barrel-shift -mxl-pattern-compare -mno-xl-soft-div -mcpu=v11.0 -mno-xl-soft-mul -mxl-multiply-high -mhard-float -mxl-float-convert -mxl-float-sqrt -Wl,--no-relax -ffunction-sections -fdata-sections -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


