/*
 * Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <internal/thread_arch.h>

#if defined(OPENSSL_THREADS_WINNT)
# include <process.h>
# include <windows.h>

static DWORD __stdcall thread_start_thunk(LPVOID vthread)
{
    CRYPTO_THREAD *thread;
    CRYPTO_THREAD_RETVAL ret;

    thread = (CRYPTO_THREAD *)vthread;

    thread->thread_id = GetCurrentThreadId();

    ret = thread->routine(thread->data);
    ossl_crypto_mutex_lock(thread->statelock);
    CRYPTO_THREAD_SET_STATE(thread, CRYPTO_THREAD_FINISHED);
    thread->retval = ret;
    ossl_crypto_condvar_broadcast(thread->condvar);
    ossl_crypto_mutex_unlock(thread->statelock);

    return 0;
}

int ossl_crypto_thread_native_spawn(CRYPTO_THREAD *thread)
{
    HANDLE *handle;

    handle = OPENSSL_zalloc(sizeof(*handle));
    if (handle == NULL)
        goto fail;

    *handle = (HANDLE)_beginthreadex(NULL, 0, &thread_start_thunk, thread, 0, NULL);
    if (*handle == NULL)
        goto fail;

    thread->handle = handle;
    return 1;

fail:
    thread->handle = NULL;
    OPENSSL_free(handle);
    return 0;
}

int ossl_crypto_thread_native_perform_join(CRYPTO_THREAD *thread, CRYPTO_THREAD_RETVAL *retval)
{
    DWORD thread_retval;
    HANDLE *handle;

    if (thread == NULL || thread->handle == NULL)
        return 0;

    handle = (HANDLE *) thread->handle;
    if (WaitForSingleObject(*handle, INFINITE) != WAIT_OBJECT_0)
        return 0;

    if (GetExitCodeThread(*handle, &thread_retval) == 0)
        return 0;

    /*
     * GetExitCodeThread call followed by this check is to make sure that
     * the thread exitted properly. In particular, thread_retval may be
     * non-zero when exitted via explicit ExitThread/TerminateThread or
     * if the thread is still active (returns STILL_ACTIVE (259)).
     */
    if (thread_retval != 0)
        return 0;

    if (CloseHandle(*handle) == 0)
        return 0;

    return 1;
}

int ossl_crypto_thread_native_exit(void)
{
    _endthreadex(0);
    return 1;
}

int ossl_crypto_thread_native_is_self(CRYPTO_THREAD *thread)
{
    return thread->thread_id == GetCurrentThreadId();
}

CRYPTO_MUTEX *ossl_crypto_mutex_new(void)
{
    CRITICAL_SECTION *mutex;

    if ((mutex = OPENSSL_zalloc(sizeof(*mutex))) == NULL)
        return NULL;
    InitializeCriticalSection(mutex);
    return (CRYPTO_MUTEX *)mutex;
}

void ossl_crypto_mutex_lock(CRYPTO_MUTEX *mutex)
{
    CRITICAL_SECTION *mutex_p;

    mutex_p = (CRITICAL_SECTION *)mutex;
    EnterCriticalSection(mutex_p);
}

int ossl_crypto_mutex_try_lock(CRYPTO_MUTEX *mutex)
{
    CRITICAL_SECTION *mutex_p;

    mutex_p = (CRITICAL_SECTION *)mutex;
    if (TryEnterCriticalSection(mutex_p))
        return 1;

    return 0;
}

void ossl_crypto_mutex_unlock(CRYPTO_MUTEX *mutex)
{
    CRITICAL_SECTION *mutex_p;

    mutex_p = (CRITICAL_SECTION *)mutex;
    LeaveCriticalSection(mutex_p);
}

void ossl_crypto_mutex_free(CRYPTO_MUTEX **mutex)
{
    CRITICAL_SECTION **mutex_p;

    mutex_p = (CRITICAL_SECTION **)mutex;
    if (*mutex_p != NULL)
        DeleteCriticalSection(*mutex_p);
    OPENSSL_free(*mutex_p);
    *mutex = NULL;
}

CRYPTO_CONDVAR *ossl_crypto_condvar_new(void)
{
    CONDITION_VARIABLE *cv_p;

    if ((cv_p = OPENSSL_zalloc(sizeof(*cv_p))) == NULL)
        return NULL;
    InitializeConditionVariable(cv_p);
    return (CRYPTO_CONDVAR *)cv_p;
}

void ossl_crypto_condvar_wait(CRYPTO_CONDVAR *cv, CRYPTO_MUTEX *mutex)
{
    CONDITION_VARIABLE *cv_p;
    CRITICAL_SECTION *mutex_p;

    cv_p = (CONDITION_VARIABLE *)cv;
    mutex_p = (CRITICAL_SECTION *)mutex;
    SleepConditionVariableCS(cv_p, mutex_p, INFINITE);
}

void ossl_crypto_condvar_wait_timeout(CRYPTO_CONDVAR *cv, CRYPTO_MUTEX *mutex,
                                      OSSL_TIME deadline, int *timeout_expired)
{
    DWORD timeout;
    CONDITION_VARIABLE *cv_p = (CONDITION_VARIABLE *)cv;
    CRITICAL_SECTION *mutex_p = (CRITICAL_SECTION *)mutex;

    if (ossl_time_is_infinite(deadline)) {
        timeout = INFINITE;
    } else {
        OSSL_TIME now = ossl_time_now();
        OSSL_TIME delta = ossl_time_subtract(deadline, now);
        uint64_t ms;

        if (ossl_time_is_zero(delta)) {
            if (timeout_expired != NULL)
                *timeout_expired = 1;

            return;
        }

        ms = ossl_time2ms(delta);

        /*
         * Amount of time we want to wait is too long for the 32-bit argument to
         * the Win32 API, so just wait as long as possible.
         */
        if (ms > (uint64_t)(INFINITE - 1))
            timeout = INFINITE - 1;
        else
            timeout = (DWORD)ms;
    }

    if (!SleepConditionVariableCS(cv_p, mutex_p, timeout)
        && timeout_expired != NULL)
        *timeout_expired = 1;
}

void ossl_crypto_condvar_broadcast(CRYPTO_CONDVAR *cv)
{
    CONDITION_VARIABLE *cv_p;

    cv_p = (CONDITION_VARIABLE *)cv;
    WakeAllConditionVariable(cv_p);
}

void ossl_crypto_condvar_free(CRYPTO_CONDVAR **cv)
{
    CONDITION_VARIABLE **cv_p;

    cv_p = (CONDITION_VARIABLE **)cv;
    OPENSSL_free(*cv_p);
    *cv_p = NULL;
}

#endif
