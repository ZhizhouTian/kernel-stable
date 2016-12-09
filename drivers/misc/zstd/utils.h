#ifndef __TESTS_H
#define __TESTS_H

#include <linux/module.h>       /* Needed by all modules */
#include <linux/kernel.h>       /* Needed for KERN_INFO */
#include <linux/init.h>         /* Needed for the macros */
#include <linux/list.h>
#include <linux/kernel.h>       /* We're doing kernel work */
#include <linux/proc_fs.h>      /* Necessary because we use the proc fs */
#include <asm/uaccess.h>        /* for copy_from_user */
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/list_sort.h>

#define read16(mem) (*(const unsigned short*)(mem))
#define read24(mem) (read16(mem) + (*((const unsigned char*)(mem) + 2) << 16))
#define read32(mem) (*(const unsigned int*)(mem))
#define read64(mem) (*(const unsigned long long*)(mem))
void test_read32(struct seq_file* m);

int is_little_endian(void);
void test_is_little_endian(struct seq_file* m);

#endif
