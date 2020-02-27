package com.igaworks.util.bolts_task;

public class ExecutorException extends RuntimeException {
    public ExecutorException(Exception e) {
        super("An exception was thrown by an Executor", e);
    }
}