# HIJACKING _IO_2_1_stdout_ TO LEAK LIBC

Chuơng trình cho ta 2 chức năng duy nhất là add_chunk và free_chunk, không có hàm nào để leak thông tin .Cùng với đó là lỗi UAF
Như đã biết trên phiên bản libc_2.23 chúng ta có thể tận dụng lỗi UAF để tạo tấn công fastbin thông qua lỗi double free và ghi vô những địa chỉ ta mong muốn.

. và địa chỉ mà ta muốn tấn công sẽ là _IO_2_1_stdout_ .

tài liệu tham khảo cho kỹ thuật này : https://hackmd.io/MZ68cAPRRmC2JcQ_WGvvaw?both

Như trong link tham khảo ta sẽ cần tạo ra 1 FAKE_CHUNK để có thể ghi lên địa chỉ _IO_2_1_stdout_ , thay đổi cấu trúc của _IO_2_1_stdout_ để leak LIBC

`File Structure sẽ có cấu trúc như sau :`

```C
{ flags: 0x0
 _IO_read_ptr: 0x0
 _IO_read_end: 0x0
 _IO_read_base: 0x0
 _IO_write_base: 0x0
 _IO_write_ptr: 0x0
 _IO_write_end: 0x0
 _IO_buf_base: 0x0
 _IO_buf_end: 0x0
 _IO_save_base: 0x0
 _IO_backup_base: 0x0
 _IO_save_end: 0x0
 markers: 0x0
 chain: 0x0
 fileno: 0x0
 _flags2: 0x0
 _old_offset: 0xffffffff
 _cur_column: 0x0
 _vtable_offset: 0x0
 _shortbuf: 0x0
 unknown1: 0x0
 _lock: 0x0
 _offset: 0xffffffffffffffff
 _codecvt: 0x0
 _wide_data: 0x0
 unknown2: 0x0
 vtable: 0x0}
```
xem cáu trúc của _IO_2_1_stdout trong gdb:

![image](https://github.com/DoQuangPhu/CTF_writeups/assets/93699926/c072f5d6-26c3-4526-b75b-16ee7bea6bc5)

Phần in đậm chính là _IO_write_base, để ý nếu ta chỉ nó đên địa chỉ 0x7ffff7dd2688 , thì sẽ có thể leak libc khi chương trình gọi đến hàm puts. 
Như trong link bên trên đã phân tích thì khi gọi đế n hàm puts thì nó đang gọi đến _IO_puts. Chương trình sẽ được in ra hàm xputsn <là một hàm trong _IO_jump_t>.
output được in ra sau khi _IO_OVERFLOW được thực hiện :

`_IO_OVERFLOW`
```C
int
_IO_new_file_overflow (FILE *f, int ch)
{
  if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
    {
      f->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return EOF;
    }
  /* If currently reading or no buffer allocated. */
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0 || f->_IO_write_base == NULL)
    {
      /* Allocate a buffer if needed. */
      if (f->_IO_write_base == NULL)
	{
	  _IO_doallocbuf (f);
	  _IO_setg (f, f->_IO_buf_base, f->_IO_buf_base, f->_IO_buf_base);
	}
      /* Otherwise must be currently reading.
	 If _IO_read_ptr (and hence also _IO_read_end) is at the buffer end,
	 logically slide the buffer forwards one block (by setting the
	 read pointers to all point at the beginning of the block).  This
	 makes room for subsequent output.
	 Otherwise, set the read pointers to _IO_read_end (leaving that
	 alone, so it can continue to correspond to the external position). */
      if (__glibc_unlikely (_IO_in_backup (f)))
	{
	  size_t nbackup = f->_IO_read_end - f->_IO_read_ptr;
	  _IO_free_backup_area (f);
	  f->_IO_read_base -= MIN (nbackup,
				   f->_IO_read_base - f->_IO_buf_base);
	  f->_IO_read_ptr = f->_IO_read_base;
	}

      if (f->_IO_read_ptr == f->_IO_buf_end)
	f->_IO_read_end = f->_IO_read_ptr = f->_IO_buf_base;
      f->_IO_write_ptr = f->_IO_read_ptr;
      f->_IO_write_base = f->_IO_write_ptr;
      f->_IO_write_end = f->_IO_buf_end;
      f->_IO_read_base = f->_IO_read_ptr = f->_IO_read_end;

      f->_flags |= _IO_CURRENTLY_PUTTING;
      if (f->_mode <= 0 && f->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
	f->_IO_write_end = f->_IO_write_ptr;
    }
  if (ch == EOF)
    return _IO_do_write (f, f->_IO_write_base,
			 f->_IO_write_ptr - f->_IO_write_base);
  if (f->_IO_write_ptr == f->_IO_buf_end ) /* Buffer is really full */
    if (_IO_do_flush (f) == EOF)
      return EOF;
  *f->_IO_write_ptr++ = ch;
  if ((f->_flags & _IO_UNBUFFERED)
      || ((f->_flags & _IO_LINE_BUF) && ch == '\n'))
    if (_IO_do_write (f, f->_IO_write_base,
		      f->_IO_write_ptr - f->_IO_write_base) == EOF)
      return EOF;
  return (unsigned char) ch;
}
libc_hidden_ver (_IO_new_file_overflow, _IO_file_overflow)
```
Ta thấy `_IO_do_write (f, f->_IO_write_base,f->_IO_write_ptr - f->_IO_write_base)` sẽ được gọi với arg là f->_IO_write_base là buffer được in ra . vậy nếu ta chỉnh f->_IO_write_base trỏ đến địa chỉ chứa libc thì ta sẽ có thể leak địa chỉ ra .
Nhưng đế hàm `_IO_do_write (f, f->_IO_write_base,f->_IO_write_ptr - f->_IO_write_base)` ta phải pass qua những check sau :

```C
 (f->_flags & _IO_NO_WRITES) /* SET ERROR */
    {
      f->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return EOF;
    }
```
phần này ta cần f->_flags & _IO_NO_WRITES ==0 để chương trình ko return ==EOF.


```C
if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0 || f->_IO_write_base == NULL)
```
ta cần (f->_flags & _IO_CURRENTLY_PUTTING) == 0 để có thể thực hiện `_IO_do_write`

```C
// các constant được define như sau:
#define _IO_MAGIC         0xFBAD0000
#define _IO_CURRENTLY_PUTTING 0x0800 
#define _IO_IS_APPENDING      0x1000
#define _IO_NO_WRITES         0x0008
```
==> flag ta cần là  _IO_MAGIC|_IO_CURRENTLY_PUTTING|_IO_IS_APPENDING



