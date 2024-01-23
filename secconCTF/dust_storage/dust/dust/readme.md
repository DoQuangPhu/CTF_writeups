# ANGR_FSROP 

# hijack I0_wide VTABLE ==> direct RCE attack IO_file struture ;

Refference link : 


https://ptr-yudai.hatenablog.com/entry/2023/02/14/033354

https://chovid99.github.io/posts/stack-the-flags-ctf-2022/?fbclid=IwAR0FLtUKhfkk4FZXysO5IelmJb_AeoxPHqPkwjn6OxGdCNTAe5TpIW98mt4 

https://blog.kylebot.net/2022/10/22/angry-FSROP/

# Source code and vulnerbility 


```C
#define TYPE_REAL    0xdeadbeefcafebabeUL
#define TYPE_STRING  0xc0b3beeffee1deadUL
typedef struct {
  union {
    double real;
    char *string;
  };
  size_t type;
} item_t;
typedef struct {
  size_t size;
  item_t *items;
} storage_t;
...
/**
 * Set the value of an item in a storage
 */
void set_item(storage_t *storage) {
  if (!storage->items) {
    print("uninitialized\n");
    return;
  }
  size_t idx  = readi("index: ");
  size_t type = readi("type [0=str / x=real]: ");
  if (type == 0) {
    storage->items[idx].type = TYPE_STRING;
  } else {
    storage->items[idx].type = TYPE_REAL;
  }
  if (idx >= storage->size) {
    print("insufficient storage size\n");
    return;
  }
  if (storage->items[idx].type == TYPE_STRING) {
    storage->items[idx].string = reads("value: ");
  } else {
    storage->items[idx].real = readf("value: ");
  }
}
```
This words was directly from author: 

```
You will immediately notice the out-of-bounds write in set_item. However, it only writes the type of an item, which is just a very big random value such as 0xdeadbeefcafebabe.

So, you have a primitive to write very big values to anywhere relative to the heap. What can we do?

First of all, you have to leak some pointers. This is not so hard.

Allocate a big chunk fit to unsorted bin.
Free the chunk and link pointers to main_arena (top of unsorted bin) are written on the heap.
Allocate a small chunk and it'll be sliced from the previously freed chunk with the link pointers left.
Read the leftover of a link pointer (recognized as REAL value)
```

This note will maily focus on how to use the kill that kylebot was publiced . (IO_wide_table hijacking )

With the vulnerbilty and the leak we can overwrite the value of `0xdeadbeefcafebabeUL` any where we want . So in this challenge , author was intended to overwrite `mp_.tcache_bins`


<img width="480" alt="image" src="https://github.com/DoQuangPhu/CTF_writeups/assets/93699926/555e67fb-286b-4656-a740-c92e993474de">



```C
void *
__libc_malloc (size_t bytes)
{
  mstate ar_ptr;
  void *victim;

  void *(*hook) (size_t, const void *)
    = atomic_forced_read (__malloc_hook);
  if (__builtin_expect (hook != NULL, 0))
    return (*hook)(bytes, RETURN_ADDRESS (0));
#if USE_TCACHE
  /* int_free also calls request2size, be careful to not pad twice.  */
  size_t tbytes;
  checked_request2size (bytes, tbytes);
  size_t tc_idx = csize2tidx (tbytes);

  MAYBE_INIT_TCACHE ();

  DIAG_PUSH_NEEDS_COMMENT;
  if (tc_idx < mp_.tcache_bins
      /*&& tc_idx < TCACHE_MAX_BINS*/ /* to appease gcc */
      && tcache
      && tcache->entries[tc_idx] != NULL)
    {
      return tcache_get (tc_idx);
    }
  DIAG_POP_NEEDS_COMMENT;
#endif

  if (SINGLE_THREAD_P)
    {
      victim = _int_malloc (&main_arena, bytes);
      assert (!victim || chunk_is_mmapped (mem2chunk (victim)) ||
	      &main_arena == arena_for_chunk (mem2chunk (victim)));
      return victim;
    }

  arena_get (ar_ptr, bytes);

  victim = _int_malloc (ar_ptr, bytes);
  /* Retry with another arena only if we were able to find a usable arena
     before.  */
  if (!victim && ar_ptr != NULL)
    {
      LIBC_PROBE (memory_malloc_retry, 1, bytes);
      ar_ptr = arena_get_retry (ar_ptr, bytes);
      victim = _int_malloc (ar_ptr, bytes);
    }

  if (ar_ptr != NULL)
    __libc_lock_unlock (ar_ptr->mutex);

  assert (!victim || chunk_is_mmapped (mem2chunk (victim)) ||
          ar_ptr == arena_for_chunk (mem2chunk (victim)));
  return victim;
}
libc_hidden_def (__libc_malloc)
```


The value of `mp_.tcache_bins` was the number of tcache bin  from size of 0x20 to 0x410 , so it wasnt ment to be change , the malloc source code when we want to request a chunk with some value of size it will check to see if that size is corresponding to tcahe size available , and if that tcache bin have a some chunk is the list ot will return that chunk .
So with the vulnerbility of arbitary of write big value like `0xdeadbeefcafebabeUL` any where we want we can write that value to `mp_.tcache_bin`  and after that we will request a chunk out side of tcache chunk size . with the set_item function we can place `_IO_list_all` address on heap chunk and malloc a chunk corresponding to that tcache[index];




```C
pwndbg> vis

0x5566598ef000	0x0000000000000000	0x0000000000000291	................
0x5566598ef010	0x0000000000010000	0x0000000000000000	................
0x5566598ef020	0x0000000000000000	0x0000000000000000	................
0x5566598ef030	0x0000000000000000	0x0000000000000000	................
0x5566598ef040	0x0000000000000000	0x0000000000000000	................
0x5566598ef050	0x0000000000000000	0x0000000000000000	................
0x5566598ef060	0x0000000000000000	0x0000000000000000	................
0x5566598ef070	0x0000000000000000	0x0000000000000000	................
0x5566598ef080	0x0000000000000000	0x0000000000000000	................
0x5566598ef090	0x0000000000000000	0x00005566598ef320	........ ..YfU..
0x5566598ef0a0	0x0000000000000000	0x0000000000000000	................
0x5566598ef0b0	0x0000000000000000	0x0000000000000000	................
0x5566598ef0c0	0x0000000000000000	0x0000000000000000	................
0x5566598ef0d0	0x0000000000000000	0x0000000000000000	................
0x5566598ef0e0	0x0000000000000000	0x0000000000000000	................
0x5566598ef0f0	0x0000000000000000	0x0000000000000000	................
0x5566598ef100	0x0000000000000000	0x0000000000000000	................
0x5566598ef110	0x0000000000000000	0x0000000000000000	................
0x5566598ef120	0x0000000000000000	0x0000000000000000	................
0x5566598ef130	0x0000000000000000	0x0000000000000000	................
0x5566598ef140	0x0000000000000000	0x0000000000000000	................
0x5566598ef150	0x0000000000000000	0x0000000000000000	................
0x5566598ef160	0x0000000000000000	0x0000000000000000	................
0x5566598ef170	0x0000000000000000	0x0000000000000000	................
0x5566598ef180	0x0000000000000000	0x0000000000000000	................
0x5566598ef190	0x0000000000000000	0x0000000000000000	................
0x5566598ef1a0	0x0000000000000000	0x0000000000000000	................
0x5566598ef1b0	0x0000000000000000	0x0000000000000000	................
0x5566598ef1c0	0x0000000000000000	0x0000000000000000	................
0x5566598ef1d0	0x0000000000000000	0x0000000000000000	................
0x5566598ef1e0	0x0000000000000000	0x0000000000000000	................
0x5566598ef1f0	0x0000000000000000	0x0000000000000000	................
0x5566598ef200	0x0000000000000000	0x0000000000000000	................
0x5566598ef210	0x0000000000000000	0x0000000000000000	................
0x5566598ef220	0x0000000000000000	0x0000000000000000	................
0x5566598ef230	0x0000000000000000	0x0000000000000000	................
0x5566598ef240	0x0000000000000000	0x0000000000000000	................
0x5566598ef250	0x0000000000000000	0x0000000000000000	................
0x5566598ef260	0x0000000000000000	0x0000000000000000	................
0x5566598ef270	0x0000000000000000	0x0000000000000000	................
0x5566598ef280	0x0000000000000000	0x0000000000000000	................
0x5566598ef290	0x0000000000000000	0x0000000000000081	................
0x5566598ef2a0	0x00000005566598ef	0x0000000000000000	..eV............
0x5566598ef2b0	0x00007f9fe0ff6680	0x414141414141000a	.f........AAAAAA

```

as you can see 0x5566598ef2b0 is having the address of `_IO_list_all` , `(0x5566598ef2b0 - 0x5566598ef090 )/8 * 0x10 + 0x20 = 0x460 ` , `0x5566598ef090 is the tcache bin chunk 0x20 ` so we need to request chunk of size 0x460 and malloc will return `_IO_list_all` for us.
Nice , This technich work also in glibc 2.27 - 2.35 . Nice 

Now let go with how to hijack _IO_file-> vtable


Remember in the good old day , with glibc 2.23 we can just overwirte _IO_FILE->vtable to some address we control and we will be able to get a shell. 

```C
pwndbg> p _IO_2_1_stdout_
$5 = {
  file = {
    _flags = -72537977,
    _IO_read_ptr = 0x7f9fe0ff6803 <_IO_2_1_stdout_+131> "",
    _IO_read_end = 0x7f9fe0ff6803 <_IO_2_1_stdout_+131> "",
    _IO_read_base = 0x7f9fe0ff6803 <_IO_2_1_stdout_+131> "",
    _IO_write_base = 0x7f9fe0ff6803 <_IO_2_1_stdout_+131> "",
    _IO_write_ptr = 0x7f9fe0ff6803 <_IO_2_1_stdout_+131> "",
    _IO_write_end = 0x7f9fe0ff6803 <_IO_2_1_stdout_+131> "",
    _IO_buf_base = 0x7f9fe0ff6803 <_IO_2_1_stdout_+131> "",
    _IO_buf_end = 0x7f9fe0ff6804 <_IO_2_1_stdout_+132> "",
    _IO_save_base = 0x0,
    _IO_backup_base = 0x0,
    _IO_save_end = 0x0,
    _markers = 0x0,
    _chain = 0x7f9fe0ff5aa0 <_IO_2_1_stdin_>,
    _fileno = 1,
    _flags2 = 0,
    _old_offset = -1,
    _cur_column = 0,
    _vtable_offset = 0 '\000',
    _shortbuf = "",
    _lock = 0x7f9fe0ff7a70 <_IO_stdfile_1_lock>,
    _offset = -1,
    _codecvt = 0x0,
    _wide_data = 0x7f9fe0ff59a0 <_IO_wide_data_1>,
    _freeres_list = 0x0,
    _freeres_buf = 0x0,
    __pad5 = 0,
    _mode = -1,
    _unused2 = '\000' <repeats 19 times>
  },
  vtable = 0x7f9fe0ff2600 <_IO_file_jumps>
}
```

But from glibc 2.24 , they added a machanism to check if the address of that vtable is in the allowed region . 
```C
static inline const struct _IO_jump_t *
IO_validate_vtable (const struct _IO_jump_t *vtable)
{
  /* Fast path: The vtable pointer is within the __libc_IO_vtables
     section.  */
  uintptr_t section_length = __stop___libc_IO_vtables - __start___libc_IO_vtables;
  uintptr_t ptr = (uintptr_t) vtable;
  uintptr_t offset = ptr - (uintptr_t) __start___libc_IO_vtables;
  if (__glibc_unlikely (offset >= section_length))
    /* The vtable pointer is not in the expected section.  Use the
       slow path, which will terminate the process if necessary.  */
    _IO_vtable_check ();
  return vtable;
}

#define _IO_OVERFLOW(FP, CH) JUMP1 (__overflow, FP, CH)

#define JUMP1(FUNC, THIS, X1) (_IO_JUMPS_FUNC(THIS)->FUNC) (THIS, X1)

# define _IO_JUMPS_FUNC(THIS) (IO_validate_vtable (_IO_JUMPS_FILE_plus (THIS)))

#define _IO_JUMPS_FILE_plus(THIS) \
  _IO_CAST_FIELD_ACCESS ((THIS), struct _IO_FILE_plus, vtable)
```
Remember that the mitigation those were implemented in the recent glibc only checks whether the vtable stored in the FILE properties is still in the correct region or not. And the standard vtable that is being used for stdfile is _IO_file_jumps. But in fact, there is a lot of other vtable in the region that we can use, and one of them is _IO_wfile_jumps. Below is the default entry of the _IO_wfile_jumps printed via gdb


```C
pwndbg> p _IO_wfile_jumps
$2 = {
  __dummy = 0,
  __dummy2 = 0,
  __finish = 0x7f069b383ff0 <_IO_new_file_finish>,
  __overflow = 0x7f069b37e390 <__GI__IO_wfile_overflow>,
  __underflow = 0x7f069b37cfd0 <__GI__IO_wfile_underflow>,
  __uflow = 0x7f069b37b840 <__GI__IO_wdefault_uflow>,
  __pbackfail = 0x7f069b37b600 <__GI__IO_wdefault_pbackfail>,
  __xsputn = 0x7f069b37e840 <__GI__IO_wfile_xsputn>,
  __xsgetn = 0x7f069b3832b0 <__GI__IO_file_xsgetn>,
  __seekoff = 0x7f069b37d750 <__GI__IO_wfile_seekoff>,
  __seekpos = 0x7f069b3864b0 <_IO_default_seekpos>,
  __setbuf = 0x7f069b3825a0 <_IO_new_file_setbuf>,
  __sync = 0x7f069b37e6a0 <__GI__IO_wfile_sync>,
  __doallocate = 0x7f069b377e90 <_IO_wfile_doallocate>,
  __read = 0x7f069b383930 <__GI__IO_file_read>,
  __write = 0x7f069b382ec0 <_IO_new_file_write>,
  __seek = 0x7f069b382670 <__GI__IO_file_seek>,
  __close = 0x7f069b382590 <__GI__IO_file_close>,
  __stat = 0x7f069b382eb0 <__GI__IO_file_stat>,
  __showmanyc = 0x7f069b387420 <_IO_default_showmanyc>,
  __imbue = 0x7f069b387430 <_IO_default_imbue>
}
```


```C
pwndbg> p _IO_wide_data_1 # _wide_data in _IO_2_1_stdout structure above
$10 = {
  _IO_read_ptr = 0x0,
  _IO_read_end = 0x0,
  _IO_read_base = 0x0,
  _IO_write_base = 0x0,
  _IO_write_ptr = 0x0,
  _IO_write_end = 0x0,
  _IO_buf_base = 0x0,
  _IO_buf_end = 0x0,
  _IO_save_base = 0x0,
  _IO_backup_base = 0x0,
  _IO_save_end = 0x0,
  _IO_state = {
    __count = 0,
    __value = {
      __wch = 0,
      __wchb = "\000\000\000"
    }
  },
  _IO_last_state = {
    __count = 0,
    __value = {
      __wch = 0,
      __wchb = "\000\000\000"
    }
  },
  _codecvt = {
    __cd_in = {
      step = 0x0,
      step_data = {
        __outbuf = 0x0,
        __outbufend = 0x0,
        __flags = 0,
        __invocation_counter = 0,
        __internal_use = 0,
        __statep = 0x0,
        __state = {
          __count = 0,
          __value = {
            __wch = 0,
            __wchb = "\000\000\000"
          }
        }
      }
    },
    __cd_out = {
      step = 0x0,
      step_data = {
        __outbuf = 0x0,
        __outbufend = 0x0,
        __flags = 0,
        __invocation_counter = 0,
        __internal_use = 0,
        __statep = 0x0,
        __state = {
          __count = 0,
          __value = {
            __wch = 0,
            __wchb = "\000\000\000"
          }
        }
      }
    }
  },
  _shortbuf = L"",
  _wide_vtable = 0x7f9fe0ff20c0 <_IO_wfile_jumps> 
}

```

Let’s try to take a look at the implementation of one of the functions which is _IO_wfile_overflow

```C
wint_t
_IO_wfile_overflow (FILE *f, wint_t wch)
{
  if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
    {
      f->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return WEOF;
    }
  /* If currently reading or no buffer allocated. */
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0)
    {
      /* Allocate a buffer if needed. */
      if (f->_wide_data->_IO_write_base == 0)
	{
	  _IO_wdoallocbuf (f);
	  ...
	}
      ...
}

void
_IO_wdoallocbuf (FILE *fp)
{
  if (fp->_wide_data->_IO_buf_base)
    return;
  if (!(fp->_flags & _IO_UNBUFFERED))
    if ((wint_t)_IO_WDOALLOCATE (fp) != WEOF)
      ...
}

#define _IO_WDOALLOCATE(FP) WJUMP0 (__doallocate, FP)

#define WJUMP0(FUNC, THIS) (_IO_WIDE_JUMPS_FUNC(THIS)->FUNC) (THIS)

#define _IO_WIDE_JUMPS_FUNC(THIS) _IO_WIDE_JUMPS(THIS)

#define _IO_WIDE_JUMPS(THIS) \
  _IO_CAST_FIELD_ACCESS ((THIS), struct _IO_FILE, _wide_data)->_wide_vtable
```


`_IO_wdoallocbuf`  was a function stored in  _IO_FILE_->`_wide_vtable`.

 There is no check if `_wide_vtable` was indeed a valid `_wide_vtable` , you can find _wide_vtable in `_IO_2_1_stdout_ structure` above .


if we able to overwrite stdin pointer in `_IO_list_all` to point to our fake_file structure we control , then we proceed to setup a file structure that sastify all the condition in `_IO_wfile_overflow` and it will jump to our controlled `_IO_wfile_doallocate` in `_wide_vtable` which we can set up to be `system` and the only argument is our IO_file struct , we can set the flag how to sastify the codtion the end with `;/bin/sh` =)).

```C
exit
|_ _IO_cleanup
   |_ _IO_flush_all_lockp
      Iterate list of available files (stderr->stdout->stdin), and on each iteration it will call:
      |_ _IO_OVERFLOW (fp, EOF)
```


```C
 void
exit (int status)
{
  __run_exit_handlers (status, &__exit_funcs, true, true);
}
```

exit call `__run_exit_handlers`

```C
void
attribute_hidden
__run_exit_handlers (int status, struct exit_function_list **listp,
		     bool run_list_atexit, bool run_dtors)
{
  /* First, call the TLS destructors.  */
#ifndef SHARED
  if (&__call_tls_dtors != NULL)
#endif
    if (run_dtors)
      __call_tls_dtors ();

  __libc_lock_lock (__exit_funcs_lock);

  /* We do it this way to handle recursive calls to exit () made by
     the functions registered with `atexit' and `on_exit'. We call
     everyone on the list and use the status value in the last
     exit (). */
  while (true)
    {
      struct exit_function_list *cur = *listp; // listp was actually call _IO_cleanup

      if (cur == NULL)
	{
	  /* Exit processing complete.  We will not allow any more
	     atexit/on_exit registrations.  */
	  __exit_funcs_done = true;
	  break;
	}

      while (cur->idx > 0)
	{
	  struct exit_function *const f = &cur->fns[--cur->idx];
	  const uint64_t new_exitfn_called = __new_exitfn_called;

	  switch (f->flavor)
	    {
	      void (*atfct) (void);
	      void (*onfct) (int status, void *arg);
	      void (*cxafct) (void *arg, int status);
	      void *arg;

	    case ef_free:
	    case ef_us:
	      break;
	    case ef_on:
	      onfct = f->func.on.fn;
	      arg = f->func.on.arg;
#ifdef PTR_DEMANGLE
	      PTR_DEMANGLE (onfct);
#endif
	      /* Unlock the list while we call a foreign function.  */
	      __libc_lock_unlock (__exit_funcs_lock);
	      onfct (status, arg);
	      __libc_lock_lock (__exit_funcs_lock);
	      break;
	    case ef_at:
	      atfct = f->func.at;
#ifdef PTR_DEMANGLE
	      PTR_DEMANGLE (atfct);
#endif
	      /* Unlock the list while we call a foreign function.  */
	      __libc_lock_unlock (__exit_funcs_lock);
	      atfct ();
	      __libc_lock_lock (__exit_funcs_lock);
	      break;
	    case ef_cxa:
	      /* To avoid dlclose/exit race calling cxafct twice (BZ 22180),
		 we must mark this function as ef_free.  */
	      f->flavor = ef_free;
	      cxafct = f->func.cxa.fn;
	      arg = f->func.cxa.arg;
#ifdef PTR_DEMANGLE
	      PTR_DEMANGLE (cxafct);
#endif
	      /* Unlock the list while we call a foreign function.  */
	      __libc_lock_unlock (__exit_funcs_lock);
	      cxafct (arg, status);
	      __libc_lock_lock (__exit_funcs_lock);
	      break;
	    }

	  if (__glibc_unlikely (new_exitfn_called != __new_exitfn_called))
	    /* The last exit function, or another thread, has registered
	       more exit functions.  Start the loop over.  */
            continue;
	}

      *listp = cur->next;
      if (*listp != NULL)
	/* Don't free the last element in the chain, this is the statically
	   allocate element.  */
	free (cur);
    }

  __libc_lock_unlock (__exit_funcs_lock);

  if (run_list_atexit)
    RUN_HOOK (__libc_atexit, ());

  _exit (status);
}
```


exit_function_list was actually will call _IO_cleanup

```C
int
_IO_cleanup (void)
{
  /* We do *not* want locking.  Some threads might use streams but
     that is their problem, we flush them underneath them.  */
  int result = _IO_flush_all_lockp (0);

  /* We currently don't have a reliable mechanism for making sure that
     C++ static destructors are executed in the correct order.
     So it is possible that other static destructors might want to
     write to cout - and they're supposed to be able to do so.

     The following will make the standard streambufs be unbuffered,
     which forces any output from late destructors to be written out. */
  _IO_unbuffer_all ();

  return result;
}

```

_IO_cleanup will call _IO_flush_all_lockp(0) ;

```C

int
_IO_flush_all_lockp (int do_lock)
{
  int result = 0;
  FILE *fp;

#ifdef _IO_MTSAFE_IO
  _IO_cleanup_region_start_noarg (flush_cleanup);
  _IO_lock_lock (list_all_lock);
#endif

  for (fp = (FILE *) _IO_list_all; fp != NULL; fp = fp->_chain)
    {
      run_fp = fp;
      if (do_lock)
	_IO_flockfile (fp);

      if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
	   || (_IO_vtable_offset (fp) == 0
	       && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
				    > fp->_wide_data->_IO_write_base))
	   )
	  && _IO_OVERFLOW (fp, EOF) == EOF)
	result = EOF;

      if (do_lock)
	_IO_funlockfile (fp);
      run_fp = NULL;
    }

#ifdef _IO_MTSAFE_IO
  _IO_lock_unlock (list_all_lock);
  _IO_cleanup_region_end (0);
#endif

  return result;
}
```

and `_IO_flush_all_lockp` will call  `_IO_list_all->_IO_OVERFLOW (fp, EOF)` all we need to do is overwite _IO_list_all pointer to point to our fake_file structure . and change fake_file-> vtable to  `_IO_wfile_jumps` and also set up 
fake_file->_wide_data->_wide_vtable to our controlled address . That should be all right to get a shell.




