#include <sanitizer/dfsan_interface.h>

extern dfsan_label mask_label[777777];

extern int label_len;

size_t __dfsw_fread(void *buf, size_t size, size_t count, FILE *fd,
             dfsan_label buf_label, dfsan_label size_label,
             dfsan_label count_label, dfsan_label fd_label,
             dfsan_label *ret_label);
