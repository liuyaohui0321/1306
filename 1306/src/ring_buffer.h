/**
 * \file ring_buffer.h
 * \brief ���׻��λ�����ض���������
 * \author netube_99\netube@163.com
 * \date 2022.08.20
 * \version v0.4.0
*/
#ifndef _RING_BUFFER_H_
#define _RING_BUFFER_H_

//����ֵ����
#define RING_BUFFER_SUCCESS     0x01
#define RING_BUFFER_ERROR       0x00

//���λ������ṹ��
typedef struct
{
    uint32_t head ;             //����ͷָ��
    uint32_t tail ;             //����βָ��
    uint32_t Length ;           //�Ѵ����������
    uint8_t *array_addr ;       //�����������������ַ
    uint32_t max_Length ;       //���������ɴ���������
}ring_buffer;

uint8_t RB_Init(ring_buffer *rb_handle, uint8_t *buffer_addr ,uint32_t buffer_size);               //��ʼ���������λ�����
uint8_t RB_Delete(ring_buffer *rb_handle, uint32_t Length);                                        //��ͷָ�뿪ʼɾ��ָ�����ȵ�����
uint8_t RB_Write_Byte(ring_buffer *rb_handle, uint8_t data);                                       //�򻺳���βָ��дһ���ֽ�
uint8_t RB_Write_String(ring_buffer *rb_handle, uint8_t *input_addr, uint32_t write_Length);       //�򻺳���βָ��дָ����������
uint8_t RB_Read_Byte(ring_buffer *rb_handle, uint8_t *output_addr);                                //�ӻ�����ͷָ���һ���ֽ�
uint8_t RB_Read_String(ring_buffer *rb_handle, uint8_t *output_addr, uint32_t read_Length);        //�ӻ�����ͷָ���ָ����������
uint32_t RB_Get_Length(ring_buffer *rb_handle);                                                    //��ȡ���������Ѵ�������ݳ���
uint32_t RB_Get_FreeSize(ring_buffer *rb_handle);                                                  //��ȡ���������ô���ռ�

#endif//#ifndef _RING_BUFFER_H_
