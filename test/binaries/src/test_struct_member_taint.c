#include <stdio.h>
#include <string.h>

typedef struct {
    char buf[32];
    char safe[32];
} Inner;

typedef struct {
    Inner inner;
    int  flag;
} Wrapper;

typedef struct {
    Inner inner;
} Holder;

static void copy_inner(Inner *dst, const Inner *src)
{
    // Taint should propagate: dst->buf depends on src->buf
    strcpy(dst->buf, src->buf);
    // But dst->safe gets only a constant; should remain untainted
    strcpy(dst->safe, "constant");
}

static void copy_wrapper(Wrapper *dst, const Wrapper *src)
{
    // Copy entire inner; taint in src->inner.buf must propagate to dst->inner.buf
    dst->inner = src->inner;
    // Flag comes from constant
    dst->flag = 42;
}

static void copy_array(Holder *dst_arr, const Holder *src_arr, int i)
{
    // Index-based member propagation: taint in src_arr[i].inner.buf must
    // propagate to dst_arr[i].inner.buf, but not to other indices.
    dst_arr[i].inner = src_arr[i].inner;
}

static void sink_printf_buf(const char *s)
{
    // SINK: should be reported when s is derived from tainted struct member(s)
    _IO_printf("TAINTED: %s\n", s);
}

static void sink_printf_safe(const char *s)
{
    // SINK: expected to be untainted for control field
    _IO_printf("SAFE: %s\n", s);
}

int main(void)
{
    Inner   a;
    Inner   b;
    Wrapper w_src;
    Wrapper w_dst;
    Holder  h_src[2];
    Holder  h_dst[2];

    // 1) Source: taint enters via a.buf
    fputs("Enter data: ", stdout);
    if (!fgets(a.buf, sizeof(a.buf), stdin))
        return 1;

    // Ensure a.safe is not tainted
    strcpy(a.safe, "not tainted");

    // 2) Direct inner copy: a -> b
    copy_inner(&b, &a);

    // 3) Wrapper path: a -> w_src.inner -> w_dst.inner
    copy_inner(&w_src.inner, &a);
    copy_wrapper(&w_dst, &w_src);

    // 4) Array path: a -> h_src[1].inner -> h_dst[1].inner
    copy_inner(&h_src[1].inner, &a);
    copy_array(h_dst, h_src, 1);

    // 5) Sinks:

    // a) Direct tainted member
    sink_printf_buf(a.buf);

    // b) Copied tainted member (simple struct-to-struct)
    sink_printf_buf(b.buf);

    // c) Nested wrapper member
    sink_printf_buf(w_dst.inner.buf);

    // d) Array element member
    sink_printf_buf(h_dst[1].inner.buf);

    // e) Control: safe field should *not* be tainted
    sink_printf_safe(b.safe);

    return 0;
}