/**
 * \file ring_buffer.c
 * \brief ���׻��λ����ʵ��
 * \author netube_99\netube@163.com
 * \date 2022.08.20
 * \version v0.4.0
*/

#include <stdint.h>
#include <string.h>
#include "ring_buffer.h"

/**
 * \brief ��ʼ���»�����
 * \param[out] rb_handle: ����ʼ���Ļ������ṹ����
 * \param[in] buffer_addr: �ⲿ����Ļ��������飬���ͱ���Ϊ uint8_t
 * \param[in] buffer_size: �ⲿ����Ļ���������ռ�
 * \return ���ػ�������ʼ���Ľ��
 *      \arg RING_BUFFER_SUCCESS: ��ʼ���ɹ�
 *      \arg RING_BUFFER_ERROR: ��ʼ��ʧ��
*/
uint8_t RB_Init(ring_buffer *rb_handle, uint8_t *buffer_addr ,uint32_t buffer_size)
{
    //����������ռ�������2��С�������������ֵ
    if(buffer_size < 2 || buffer_size == 0xFFFFFFFF)
        return RING_BUFFER_ERROR ; //��ʼ��ʧ��
    rb_handle->head = 0 ; //��λͷָ��
    rb_handle->tail = 0 ; //��λβָ��
    rb_handle->Length = 0 ; //��λ�Ѵ洢���ݳ���
    rb_handle->array_addr = buffer_addr ; //�����������������ַ
    rb_handle->max_Length = buffer_size ; //���������ɴ���������
    return RING_BUFFER_SUCCESS ; //��������ʼ���ɹ�
}

/**
 * \brief ��ͷָ�뿪ʼɾ��ָ�����ȵ�����
 * \param[out] rb_handle: �������ṹ����
 * \param[in] Length: Ҫɾ���ĳ���
 * \return ����ɾ��ָ���������ݽ��
 *      \arg RING_BUFFER_SUCCESS: ɾ���ɹ�
 *      \arg RING_BUFFER_ERROR: ɾ��ʧ��
*/
uint8_t RB_Delete(ring_buffer *rb_handle, uint32_t Length)
{
    if(rb_handle->Length < Length)
        return RING_BUFFER_ERROR ;//�Ѵ����������С����ɾ����������
    else
    {
        if((rb_handle->head + Length) >= rb_handle->max_Length)
            rb_handle->head = Length - (rb_handle->max_Length - rb_handle->head);
        else
            rb_handle->head += Length ;    //ͷָ����ǰ�ƽ�����������
        rb_handle->Length -= Length ;      //���¼�¼��Ч���ݳ���
        return RING_BUFFER_SUCCESS ;//�Ѵ����������С����ɾ����������
    }
}

/**
 * \brief �򻺳���β��дһ���ֽ�
 * \param[out] rb_handle: �������ṹ����
 * \param[in] data: Ҫд����ֽ�
 * \return ���ػ�����д�ֽڵĽ��
 *      \arg RING_BUFFER_SUCCESS: д��ɹ�
 *      \arg RING_BUFFER_ERROR: д��ʧ��
*/
uint8_t RB_Write_Byte(ring_buffer *rb_handle, uint8_t data)
{
    //�����������������������Ǵ���
    if(rb_handle->Length == (rb_handle->max_Length))
        return RING_BUFFER_ERROR ;
    else
    {
        *(rb_handle->array_addr + rb_handle->tail) = data;//����ַ+ƫ�������������
        rb_handle->Length ++ ;//����������+1
        rb_handle->tail ++ ;//βָ�����
    }
    //���βָ�볬Խ������ĩβ��βָ��ָ�򻺳������鿪ͷ���γɱջ�
    if(rb_handle->tail > (rb_handle->max_Length - 1))
        rb_handle->tail = 0 ;
	return RING_BUFFER_SUCCESS ;
}

/**
 * \brief �ӻ�����ͷָ���ȡһ���ֽ�
 * \param[out] rb_handle: �������ṹ����
 * \param[out] output_addr: ��ȡ���ֽڱ����ַ
 * \return ���ض�ȡ״̬
 *      \arg RING_BUFFER_SUCCESS: ��ȡ�ɹ�
 *      \arg RING_BUFFER_ERROR: ��ȡʧ��
*/
uint8_t RB_Read_Byte(ring_buffer *rb_handle, uint8_t *output_addr)
{
    if (rb_handle->Length != 0)//������δ����
    {
        *output_addr = *(rb_handle->array_addr + rb_handle->head);//��ȡ����
        rb_handle->head ++ ;
        rb_handle->Length -- ;//����������-1
        //���ͷָ�볬Խ������ĩβ��ͷָ��ָ�����鿪ͷ���γɱջ�
        if(rb_handle->head > (rb_handle->max_Length - 1))
            rb_handle->head = 0 ;
        return RING_BUFFER_SUCCESS ;
    }
    return RING_BUFFER_ERROR ;
}

/**
 * \brief �򻺳���β��дָ�����ȵ�����
 * \param[out] rb_handle: �������ṹ����
 * \param[out] input_addr: ��д�����ݵĻ���ַ
 * \param[in] write_Length: Ҫд����ֽ���
 * \return ���ػ�����β��дָ�������ֽڵĽ��
 *      \arg RING_BUFFER_SUCCESS: д��ɹ�
 *      \arg RING_BUFFER_ERROR: д��ʧ��
*/
uint8_t RB_Write_String(ring_buffer *rb_handle, uint8_t *input_addr, uint32_t write_Length)
{
    //��������洢�ռ���������,���ش���
    if((rb_handle->Length + write_Length) > (rb_handle->max_Length))
        return RING_BUFFER_ERROR ;
    else
    {
        //��������д�볤��
        uint32_t write_size_a, write_size_b ;
        //���˳����ó���С����д��ĳ��ȣ���Ҫ�����ݲ�����ηֱ�д��
        if((rb_handle->max_Length - rb_handle->tail) < write_Length)
        {
            write_size_a = rb_handle->max_Length - rb_handle->tail ;//��βָ�뿪ʼд����������ĩβ
            write_size_b = write_Length - write_size_a ;//�Ӵ������鿪ͷд����
            //�ֱ𿽱�a��b�����ݵ�����������
            memcpy(rb_handle->array_addr + rb_handle->tail, input_addr, write_size_a);
            memcpy(rb_handle->array_addr, input_addr + write_size_a, write_size_b);
            rb_handle->Length += write_Length ;//��¼�´洢�˶���������
            rb_handle->tail = write_size_b ;//���¶�λβָ��λ��
        }
        else//���˳����ó��ȴ��ڻ������д��ĳ��ȣ���ֻ��Ҫд��һ��
        {
            write_size_a = write_Length ;//��βָ�뿪ʼд����������ĩβ
            memcpy(rb_handle->array_addr + rb_handle->tail, input_addr, write_size_a);
            rb_handle->Length += write_Length ;//��¼�´洢�˶���������
            rb_handle->tail += write_size_a ;//���¶�λβָ��λ��
            if(rb_handle->tail == rb_handle->max_Length)
                rb_handle->tail = 0 ;//���д�����ݺ�βָ��պ�д������β������ص���ͷ����ֹԽλ
        }
        return RING_BUFFER_SUCCESS ;
    }
}

/**
 * \brief �ӻ�����ͷ����ָ�����ȵ����ݣ����浽ָ���ĵ�ַ
 * \param[out] rb_handle: �������ṹ����
 * \param[out] output_addr: ��ȡ�����ݱ����ַ
 * \param[in] read_Length: Ҫ��ȡ���ֽ���
 * \return ���ػ�����ͷ����ָ�������ֽڵĽ��
 *      \arg RING_BUFFER_SUCCESS: ��ȡ�ɹ�
 *      \arg RING_BUFFER_ERROR: ��ȡʧ��
*/
uint8_t RB_Read_String(ring_buffer *rb_handle, uint8_t *output_addr, uint32_t read_Length)
{
    if(read_Length > rb_handle->Length)
        return RING_BUFFER_ERROR ;
    else
    {
        uint32_t Read_size_a, Read_size_b ;
        if(read_Length > (rb_handle->max_Length - rb_handle->head))
        {
            Read_size_a = rb_handle->max_Length - rb_handle->head ;
            Read_size_b = read_Length - Read_size_a ;
            memcpy(output_addr, rb_handle->array_addr + rb_handle->head, Read_size_a);
            memcpy(output_addr + Read_size_a, rb_handle->array_addr, Read_size_b);
            rb_handle->Length -= read_Length ;//��¼ʣ��������
            rb_handle->head = Read_size_b ;//���¶�λͷָ��λ��
        }
        else
        {
            Read_size_a = read_Length ;
            memcpy(output_addr, rb_handle->array_addr + rb_handle->head, Read_size_a);
            rb_handle->Length -= read_Length ;//��¼ʣ��������
            rb_handle->head += Read_size_a ;//���¶�λͷָ��λ��
            if(rb_handle->head == rb_handle->max_Length)
                rb_handle->head = 0 ;//�����ȡ���ݺ�ͷָ��պ�д������β������ص���ͷ����ֹԽλ
        }
        return RING_BUFFER_SUCCESS ;
    }
}

/**
 * \brief ��ȡ���������Ѵ�������ݳ���
 * \param[in] rb_handle: �������ṹ����
 * \return ���ػ��������Ѵ�������ݳ���
*/
uint32_t RB_Get_Length(ring_buffer *rb_handle)
{
    return rb_handle->Length ;
}

/**
 * \brief ��ȡ���������ô���ռ�
 * \param[in] rb_handle: �������ṹ����
 * \return ���ػ��������ô���ռ�
*/
uint32_t RB_Get_FreeSize(ring_buffer *rb_handle)
{
    return (rb_handle->max_Length - rb_handle->Length) ;
}

