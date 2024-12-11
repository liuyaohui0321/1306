/*
 * File:		alloc.c
 * Purpose: 	generic malloc() and free() engine
 *
 * Notes:		99% of this code stolen/borrowed from the K&R C
 *				examples.
 *
 */
#include "stdlib.h"
#include "alloc.h"
/*
ʹ�ñ���������Ķ���Ϊ�ڴ�أ�ע�⣬ֱ��ʹ��malloc�������C��ĺ�����ʹ�õľ��Ƕѣ�
Ҫ��ֹ��ͻ
*/
//#define ALLOC_USE_HEAP	//�ö����ڴ��
#define ALLOC_USE_ARRAY //�ö�����������ڴ��

/* 
�ڴ���䷽��ѡ��
_ALLOC_BEST_FIT_ ����Ӧ��
_ALLOC_FIRST_FIT_ �״���Ӧ��
*/
#define _ALLOC_BEST_FIT_	
//#define _ALLOC_FIRST_FIT_

#ifdef ALLOC_USE_HEAP
#pragma section = "HEAP"
#endif

#ifdef ALLOC_USE_ARRAY
//#define AllocArraySize (76*1024)
//#define AllocArraySize (4*76*1024)   //3.26�Ĵ� by lyh
#define AllocArraySize (10*1024*1024)

//__align(4) //��֤�ڴ�����ֽڶ���
__attribute__ ((aligned(4))) //��֤�ڴ�����ֽڶ���
char AllocArray[AllocArraySize];

#endif

/********************************************************************/

/*
 * This struct forms the minimum block size which is allocated, and
 * also forms the linked list for the memory space used with alloc()
 * and free().	It is padded so that on a 32-bit machine, all malloc'ed
 * pointers are 16-byte aligned.
 */
/*
	���ڴ���䷽��������Ľṹ������������ṹ�塣
	��ÿһ������ڴ��ͷ������һ����
	����ṹ��size��¼�˱����ڴ�Ĵ�С,
	ptr�����ӵ���һ������ڴ档
	�����ڴ�ʱ����һ������ڴ��и���Ҫ���ڴ��ȥ��

*/
typedef struct ALLOC_HDR
{
	struct 
	{
		struct ALLOC_HDR*ptr;
		unsigned int size;									/*�����ڴ�����*/
	} s;


unsigned int align;
unsigned int pad;
} ALLOC_HDR;


static ALLOC_HDR base; /*�����ڴ�����ͷ���*/
static ALLOC_HDR*freep = NULL;


uint32_t AllocCnt = 0;

/*-------------------------------------------------------------------*/
void wjq_free_t(void*ap)
{
	ALLOC_HDR*bp, *p;

	/* ��õ��ж��ǲ���Ӧ���ж��ڶѷ�Χ�ڣ�*/
	if(ap==NULL)
		return;

	/* ���������ap�ǿ�ʹ���ڴ��ָ�룬��ǰ��һ���ṹ��λ�ã�
		Ҳ���������bp�����Ǽ�¼�ڴ���Ϣ��λ��*/
	bp = (ALLOC_HDR*)ap-1;											/* point to block header */

	AllocCnt -= bp->s.size;

	/*
	  �ҵ���Ҫ�ͷŵ��ڴ��ǰ����п�
	  ��ʵ���ǱȽ��ڴ��λ�õĵ�ַ��С
	*/
	for(p = freep; ! ((bp>p)&&(bp<p->s.ptr)); p = p->s.ptr)
	{
		if((p>=p->s.ptr)&&((bp>p)||(bp<p->s.ptr)))
		{
			/*
				��һ���飬
				p>=p->s.ptr ������ʼ��ַָ�������һ���ַָ��
				bp>p Ҫ�ͷŵĿ飬��ַ����P
				bp<p->s.ptr Ҫ�ͷŵĿ飬��ַС����һ��
			*/
			break;		/* freed block at start or end of arena */
		}
	}

	/*�ж��Ƿ��ܸ�һ����ϲ����ܺϲ��ͺϲ������ܺϲ���������������*/
	if((bp+bp->s.size)==p->s.ptr)
	{
		bp->s.size += p->s.ptr->s.size;
		bp->s.ptr = p->s.ptr->s.ptr;
	}
	else
	{
		bp->s.ptr = p->s.ptr;
	}

	/*ͬ���������һ��Ĺ�ϵ*/
	if((p+p->s.size)==bp)
	{
		p->s.size += bp->s.size;
		p->s.ptr = bp->s.ptr;
	}
	else
	{
		p->s.ptr = bp;
	}

	freep = p;

}


/*---------------------------------------------------------*/
void*wjq_malloc_t(unsigned nbytes)
{
	/* Get addresses for the HEAP start and end */
#ifdef ALLOC_USE_HEAP
	char*__HEAP_START = __section_begin("HEAP");
	char*__HEAP_END = __section_end("HEAP");
#endif

#ifdef ALLOC_USE_ARRAY
	char*__HEAP_START = AllocArray;
	char*__HEAP_END = __HEAP_START+AllocArraySize;
#endif

	ALLOC_HDR*p, *prevp;
	unsigned nunits;

#ifdef _ALLOC_BEST_FIT_
	ALLOC_HDR *bp = NULL;
    ALLOC_HDR *bprevp;
#endif

	/*����Ҫ������ڴ����*/
	nunits = ((nbytes+sizeof(ALLOC_HDR)-1) / sizeof(ALLOC_HDR))+1;

	AllocCnt += nunits;
	//wjq_log(LOG_DEBUG, "AllocCnt:%d\r\n", AllocCnt*sizeof(ALLOC_HDR));

	/*��һ��ʹ��malloc���ڴ�����û�н���
	  ��ʼ������*/
	if((prevp = freep)==NULL)
	{
		p = (ALLOC_HDR*)
		__HEAP_START;
		p->s.size = (((uint32_t) __HEAP_END- (uint32_t) __HEAP_START) / sizeof(ALLOC_HDR));
		p->s.ptr =&base;
		base.s.ptr = p;
		base.s.size = 0;
		prevp = freep =&base;

		/*������ʼ����ֻ��һ����п�*/
	}

	/*��ѯ�������Һ��ʿ�*/
	for(p = prevp->s.ptr; ; prevp = p, p = p->s.ptr)
	{

		if(p->s.size==nunits)
		{
			prevp->s.ptr = p->s.ptr;
			freep = prevp;

			/*���ؿ����ڴ�ָ����û���
			�����ڴ�Ҫ��ȥ�ڴ�����ṹ��*/
			return (void*) (p+1);
		}
		else if(p->s.size > nunits)
		{
			#ifdef _ALLOC_BEST_FIT_/*���ʺϷ�*/
			if(bp == NULL)
            {
                bp = p;
                bprevp = prevp;
            }
			
            if(bp->s.size > p->s.size)
            {
                bprevp = prevp;
                bp = p;                
            }
			#else/*�״���Ӧ��*/
			p->s.size -= nunits;
			p += p->s.size;
			p->s.size = nunits;

			freep = prevp;
			/*���ؿ����ڴ�ָ����û���
			�����ڴ�Ҫ��ȥ�ڴ�����ṹ��*/
			return (void*) (p+1);
			#endif
		}

		/*����ʧ��*/
		if(p==freep)
		{
			#ifdef _ALLOC_BEST_FIT_
			if(bp != NULL)
			{
                freep = bprevp;
                p = bp;
                
                p->s.size -= nunits;
                p += p->s.size;     //P ָ�򽫷����ȥ�Ŀռ�
                p->s.size = nunits; //��¼����Ĵ�С�����ﲻ������ptr�ˣ���Ϊ�������ȥ��

                return (void *)(p + 1); //��ȥͷ�ṹ���������������ڴ�    
            }
			#endif
			
			while(1)
			{
				/*����Ƕ��ʽ��˵��û�л��������ڴ棬��ˣ��������ڴ����ʧ��*/
//				wjq_log(LOG_ERR, "wujique malloc err!!\r\n");
				xil_printf("wujique malloc err!!\r\n");
			}
			return NULL;
		}

	}
}

/*
	���η�װ�������Ҫ�����⣬��_m��׺�ĺ�����ʵ�֡�
*/
void*wjq_malloc_m(unsigned nbytes)
{
	void*p;
	//wjq_log(LOG_DEBUG, "malloc:%d\r\n", nbytes);
	
	p = wjq_malloc_t(nbytes);

	return p;
}


void wjq_free_m(void*ap)
{
	if(ap==NULL)
		return;
	
	wjq_free_t(ap);
}


void*wjq_calloc(size_t n, size_t size)
{
	void *p;

	//wjq_log(LOG_DEBUG, "wjq_calloc\r\n");

	p = wjq_malloc_t(n*size);

	if(p!=NULL)
	{
		memset((char*) p, 0, n*size);
	}
	return p;
}

void *wjq_realloc(void *ap, unsigned int newsize)
{
	ALLOC_HDR*bp, *p, *np;
	
	unsigned nunits;
	unsigned aunits;

	
	//wjq_log(LOG_DEBUG, "wjq_realloc: %d\r\n", newsize);

	if(ap == NULL)
	{
		bp = wjq_malloc_t(newsize);
		return bp;	
	}

	if(newsize == 0)
	{
		wjq_free(ap);
		return NULL;
	}
	/*����Ҫ������ڴ����*/
	nunits = ((newsize + sizeof(ALLOC_HDR)-1) / sizeof(ALLOC_HDR))+1;

	/* ���������ap�ǿ�ʹ���ڴ��ָ�룬��ǰ��һ���ṹ��λ�ã�
		Ҳ���������bp�����Ǽ�¼�ڴ���Ϣ��λ��*/
	bp = (ALLOC_HDR*)ap-1;											/* point to block header */
	if(nunits <= bp->s.size)
	{
		/*
		�µ�����������ԭ���Ĵ���ʱ������
		�˷ѵ��ڴ档
		*/
		return ap;
	}
	
	#if 1
	/*������ζ�ֱ�������ڴ�Ȼ�󿽱�����*/
	bp = wjq_malloc_t(newsize);
	memcpy(bp, ap, newsize);
	wjq_free(ap);
	
	return bp;
	#else
	/*
	  �ҵ���Ҫ�ͷŵ��ڴ��ǰ����п�
	  ��ʵ���ǱȽ��ڴ��λ�õĵ�ַ��С
	*/
	for(p = freep; ! ((bp>p)&&(bp<p->s.ptr)); p = p->s.ptr)
	{
		if((p>=p->s.ptr)&&((bp>p)||(bp<p->s.ptr)))
		{
			/*
				��һ���飬
				p>=p->s.ptr ������ʼ��ַָ�������һ���ַָ��
				bp>p Ҫ�ͷŵĿ飬��ַ����P
				bp<p->s.ptr Ҫ�ͷŵĿ飬��ַС����һ��
			*/
			break;		/* freed block at start or end of arena */
		}
	}

	/**/
	if((bp + bp->s.size) == p->s.ptr)
	{
		/*���ӵ��ڴ��*/
		aunits = (nunits - bp->s.size);
		if( aunits == p->s.ptr->s.size)
		{	
			/*�ոպ����*/
			p->s.ptr = p->s.ptr->s.ptr;
			bp->s.size = nunits;
			return ap;
		}
		else if(aunits < p->s.ptr->s.size)
		{
			np = p->s.ptr + aunits;//�и�aunits�ֳ�ȥ��np����ʣ�¿�ĵ�ַ
			np->s.ptr = p->s.ptr->s.ptr;
			np->s.size = p->s.ptr->s.size - aunits;
				
			p->s.ptr = np;

			bp->s.size = nunits;
			return ap;
		}
		
	}
	
	/*��Ҫ���������ڴ�*/
	bp = wjq_malloc_t(newsize);
	memcpy(bp, ap, newsize);
	wjq_free(ap);
	
	return bp;
	#endif
	
}

void wjq_malloc_test(void)
{
	char*p;

	p = (char*)
	wjq_malloc(1024);

	/*��ӡָ�룬�����ǲ���4�ֽڶ���*/
//	wjq_log(LOG_FUN, "pointer :%08x\r\n", p);

	memset(p, 0xf0, 1024);
//	wjq_log(LOG_FUN, "data:%02x\r\n", * (p+1023));
//	wjq_log(LOG_FUN, "data:%02x\r\n", * (p+1024));

	wjq_free(p);
//	wjq_log(LOG_FUN, "alloc free ok\r\n");

	while(1)
		;
}


/***************************** end ***************************************/

