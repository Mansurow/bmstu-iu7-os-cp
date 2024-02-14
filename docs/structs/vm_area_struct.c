struct vm_area_struct {

	unsigned long vm_start;	/* Our start address within vm_mm. */
	unsigned long vm_end;  /* The first byte after our end address within vm_mm. */

	/* linked list of VM areas per task, sorted by address */
	struct vm_area_struct *vm_next, *vm_prev;
    ...
	struct mm_struct *vm_mm; /* The address space we belong to. */
    ...
	unsigned long vm_flags;	/* Flags, see mm.h. */
    ...
    /* Serialized by mmap_lock &
	 * page_table_lock */
	struct list_head anon_vma_chain; 
	struct anon_vma *anon_vma;	/* Serialized by page_table_lock */

	/* Function pointers to deal with this struct. */
	const struct vm_operations_struct *vm_ops;

	/* Information about our backing store: */
    /* Offset (within vm_file) in PAGE_SIZE units */
	unsigned long vm_pgoff;		
	struct file * vm_file;  /* File we map to (can be NULL). */
	void * vm_private_data;	/* was vm_pte (shared mem) */
} __randomize_layout;