package com.igaworks.util.bolts_task;

import android.util.Log;
import com.igaworks.core.IgawConstant;
import java.util.concurrent.CancellationException;
import java.util.concurrent.TimeUnit;

public class TaskUtils {
    public static <T> T wait(Task<T> task) throws Exception {
        try {
            if (!task.waitForCompletion(15000, TimeUnit.MILLISECONDS)) {
                Log.d(IgawConstant.QA_TAG, "Task is timeout. Release lock.");
                return null;
            } else if (task.isFaulted()) {
                Exception error = task.getError();
                if (error instanceof RuntimeException) {
                    throw ((RuntimeException) error);
                }
                throw new RuntimeException(error);
            } else if (!task.isCancelled()) {
                return task.getResult();
            } else {
                throw new RuntimeException(new CancellationException());
            }
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    public static <T> T forceWait(Task<T> task) throws Exception {
        try {
            task.waitForCompletion();
            if (task.isFaulted()) {
                Exception error = task.getError();
                if (error instanceof RuntimeException) {
                    throw ((RuntimeException) error);
                }
                throw new RuntimeException(error);
            } else if (!task.isCancelled()) {
                return task.getResult();
            } else {
                throw new RuntimeException(new CancellationException());
            }
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    public static <T> T wait(Task<T> task, long duration, TimeUnit timeUnit) throws Exception {
        try {
            if (!task.waitForCompletion(duration, timeUnit)) {
                throw new RuntimeException("TimeOut");
            } else if (task.isFaulted()) {
                Exception error = task.getError();
                if (error instanceof RuntimeException) {
                    throw ((RuntimeException) error);
                }
                throw new RuntimeException(error);
            } else if (!task.isCancelled()) {
                return task.getResult();
            } else {
                throw new RuntimeException(new CancellationException());
            }
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }
}