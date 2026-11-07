package com.cipherbird.cb2;

import java.lang.ref.Cleaner;
import java.util.function.LongConsumer;
import java.util.function.LongFunction;

/**
 * The native handle of one key, shared safely between threads. Any number
 * of calls may use the handle at once; a call that changes the key waits
 * until no other call is using it. Closing marks the handle closed at
 * once, so later calls throw IllegalStateException, and frees the native
 * key when the last call in flight returns. A key that is never closed is
 * freed by the cleaner once it becomes unreachable.
 */
final class NativeHandle {
    private static final Cleaner CLEANER = Cleaner.create();

    private final String what;
    private final LongConsumer free;
    private long value;
    private int users;
    private boolean closed;

    private NativeHandle(String what, long value, LongConsumer free) {
        this.what = what;
        this.value = value;
        this.free = free;
    }

    static NativeHandle of(Object owner, String what, long value, LongConsumer free) {
        NativeHandle handle = new NativeHandle(what, value, free);
        CLEANER.register(owner, handle::close);
        return handle;
    }

    <T> T use(LongFunction<T> call) {
        long h = acquire();
        try {
            return call.apply(h);
        } finally {
            release();
        }
    }

    synchronized void change(LongConsumer call) {
        boolean interrupted = false;
        while (users > 0) {
            try {
                wait();
            } catch (InterruptedException e) {
                interrupted = true;
            }
        }
        if (interrupted) {
            Thread.currentThread().interrupt();
        }
        if (closed) {
            throw new IllegalStateException(what + " is closed");
        }
        call.accept(value);
    }

    synchronized void close() {
        if (closed) {
            return;
        }
        closed = true;
        freeWhenIdle();
    }

    private synchronized long acquire() {
        if (closed) {
            throw new IllegalStateException(what + " is closed");
        }
        users++;
        return value;
    }

    private synchronized void release() {
        users--;
        if (users == 0) {
            notifyAll();
            freeWhenIdle();
        }
    }

    private void freeWhenIdle() {
        if (closed && users == 0 && value != 0) {
            long h = value;
            value = 0;
            free.accept(h);
        }
    }
}
