#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <inttypes.h>
#include <sanitizer/dfsan_interface.h>
#include <stdlib.h>

static int granularity = 1; // byte level

char str[200];
dfsan_label mask_label[777777];

int label_len = 0;

static void assign_taint_labels(void *buf, long offset, size_t size) {
  for (size_t i = 0; i < size; i += granularity) {
    sprintf(str, "%d", offset+i);
    dfsan_label L = dfsan_create_label(str, 0);
    //dfsan_label L = dfsan_create_label("1",0);
    mask_label[offset + i] = L;
    dfsan_set_label(L, (char *)(buf) + offset + i, granularity);
  }
  label_len = offset + size;
}

static void assign_taint_labels_exf(void *buf, long offset, size_t ret,
                                    size_t count, size_t size) {
  if (offset < 0)
    offset = 0;
  // if count is not so huge!
  int len = ret * size;
  if (ret < count) {
    int res = (count - ret) * size;
    if (res < 1024) {
      len += res;
    } else {
      len += 1024;
    }
  }
  assign_taint_labels(buf, offset, len);
}

size_t __dfsw_fread(void *buf, size_t size, size_t count, FILE *fd,
             dfsan_label buf_label, dfsan_label size_label,
             dfsan_label count_label, dfsan_label fd_label,
             dfsan_label *ret_label) {
  long offset = ftell(fd);
  size_t ret = fread(buf, size, count, fd);
#ifdef DEBUG_INFO
  fprintf(stderr, "### fread %p,range is %ld, %ld  --  (size %d, count %d)\n",
          fd, offset, ret, size, count);
#endif
  assign_taint_labels_exf(buf, offset, ret, count, size);
  //assign ret_label?
  return ret;
}