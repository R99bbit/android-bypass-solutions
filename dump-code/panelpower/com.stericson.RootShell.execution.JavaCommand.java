package com.stericson.RootShell.execution;

import android.content.Context;

public class JavaCommand extends Command {
    public void commandCompleted(int i, int i2) {
    }

    public void commandTerminated(int i, String str) {
    }

    public JavaCommand(int i, Context context, String... strArr) {
        super(i, strArr);
        this.context = context;
        this.javaCommand = true;
    }

    public JavaCommand(int i, boolean z, Context context, String... strArr) {
        super(i, z, strArr);
        this.context = context;
        this.javaCommand = true;
    }

    public JavaCommand(int i, int i2, Context context, String... strArr) {
        super(i, i2, strArr);
        this.context = context;
        this.javaCommand = true;
    }

    public void commandOutput(int i, String str) {
        super.commandOutput(i, str);
    }
}