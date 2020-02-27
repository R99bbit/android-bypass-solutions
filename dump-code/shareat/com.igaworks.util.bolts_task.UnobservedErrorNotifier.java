package com.igaworks.util.bolts_task;

import com.igaworks.util.bolts_task.Task.UnobservedExceptionHandler;

class UnobservedErrorNotifier {
    private Task<?> task;

    public UnobservedErrorNotifier(Task<?> task2) {
        this.task = task2;
    }

    /* access modifiers changed from: protected */
    public void finalize() throws Throwable {
        try {
            Task faultedTask = this.task;
            if (faultedTask != null) {
                UnobservedExceptionHandler ueh = Task.getUnobservedExceptionHandler();
                if (ueh != null) {
                    ueh.unobservedException(faultedTask, new UnobservedTaskException(faultedTask.getError()));
                }
            }
        } finally {
            super.finalize();
        }
    }

    public void setObserved() {
        this.task = null;
    }
}