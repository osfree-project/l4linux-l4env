/*
 * This header file defines the L4Linux internal interface for
 * memory handling functionality. All APIs have to implement it.
 *
 * $Id: memory.h,v 1.1 2003/02/11 17:53:38 adam Exp $
 */
#ifndef __ASM_L4__L4LXAPI__MEMORY_H__
#define __ASM_L4__L4LXAPI__MEMORY_H__

/**
 * \defgroup memory Memory handling functions.
 * \ingroup l4lxapi
 */

/**
 * \brief Map a page into the virtual address space.
 * \ingroup memory
 * 
 * \param	address		Virtual address.
 * \param	page		Physical address.
 *
 * \return	0 on success, != 0 on error
 */
int l4lx_memory_map_virtual_page(unsigned long address, unsigned long page);

/**
 * \brief Unmap a page from the virtual address space.
 * \ingroup memory
 *
 * \param	address		Virtual adress.
 *
 * \return	0 on success, != 0 on error
 */
int l4lx_memory_unmap_virtual_page(unsigned long address);

/**
 * \brief Return if something is mapped at given address
 * \ingroup memory
 *
 * \param	address		Address to query
 *
 * \return	1 if a page is mapped, 0 if not
 */
int l4lx_memory_page_mapped(unsigned long address);

#endif /* ! __ASM_L4__L4LXAPI__MEMORY_H__ */
