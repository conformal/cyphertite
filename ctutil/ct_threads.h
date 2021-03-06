/*
 * Copyright (c) 2012 Conformal Systems LLC <info@conformal.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _CT_THREADS_H_
#define _CT_THREADS_H_

#if defined(_POSIX_THREADS) || defined(_REENTRANT)
#define CT_ENABLE_THREADS 1
#define CT_ENABLE_PTHREADS 1
#else
#define CT_ENABLE_THREADS 0
#define CT_ENABLE_PTHREADS 0
#endif

#if CT_ENABLE_PTHREADS
#include <pthread.h>

#ifndef CT_LOCK_STORE
#define CT_LOCK_STORE(var) pthread_mutex_t var
#endif
#ifndef CT_LOCK
#define CT_LOCK(var) pthread_mutex_lock(var)
#endif
#ifndef CT_UNLOCK
#define CT_UNLOCK(var) pthread_mutex_unlock(var)
#endif
#ifndef CT_LOCK_INIT
#define CT_LOCK_INIT(var)  pthread_mutex_init(var, NULL)
#endif
#ifndef CT_LOCK_RELEASE
#define CT_LOCK_RELEASE(var) pthread_mutex_destroy(var)
#endif
#else
#ifndef CT_LOCK_STORE
#define CT_LOCK_STORE(var) /* empty */
#endif
#ifndef CT_LOCK
#define CT_LOCK(var) /* empty */
#endif
#ifndef CT_UNLOCK
#define CT_UNLOCK(var) /* empty */
#endif
#ifndef CT_LOCK_INIT
#define CT_LOCK_INIT(var)  /* empty */
#endif
#ifndef CT_LOCK_RELEASE
#define CT_LOCK_RELEASE(var) /* empty */
#endif
#endif

#endif /* _CT_THREADS_H_ */
