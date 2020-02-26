package com.stericson.RootShell.execution;

import android.content.Context;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import com.stericson.RootShell.RootShell;
import java.io.IOException;

public class Command {
    String[] command = new String[0];
    protected Context context = null;
    boolean executing = false;
    ExecutionMonitor executionMonitor = null;
    int exitCode = -1;
    boolean finished = false;
    boolean handlerEnabled = true;
    int id = 0;
    protected boolean javaCommand = false;
    Handler mHandler = null;
    boolean terminated = false;
    int timeout = RootShell.defaultCommandTimeout;
    public int totalOutput = 0;
    public int totalOutputProcessed = 0;

    private class CommandHandler extends Handler {
        public static final String ACTION = "action";
        public static final int COMMAND_COMPLETED = 2;
        public static final int COMMAND_OUTPUT = 1;
        public static final int COMMAND_TERMINATED = 3;
        public static final String TEXT = "text";

        private CommandHandler() {
        }

        public final void handleMessage(Message message) {
            int i = message.getData().getInt(ACTION);
            String string = message.getData().getString("text");
            if (i == 1) {
                Command command = Command.this;
                command.commandOutput(command.id, string);
            } else if (i == 2) {
                Command command2 = Command.this;
                command2.commandCompleted(command2.id, Command.this.exitCode);
            } else if (i == 3) {
                Command command3 = Command.this;
                command3.commandTerminated(command3.id, string);
            }
        }
    }

    private class ExecutionMonitor extends Thread {
        private ExecutionMonitor() {
        }

        /* JADX WARNING: Exception block dominator not found, dom blocks: [] */
        /* JADX WARNING: Missing exception handler attribute for start block: B:9:0x001c */
        /* JADX WARNING: Removed duplicated region for block: B:13:0x0023  */
        /* JADX WARNING: Removed duplicated region for block: B:19:0x0006 A[SYNTHETIC] */
        public void run() {
            if (Command.this.timeout > 0) {
                while (!Command.this.finished) {
                    synchronized (Command.this) {
                        Command.this.wait((long) Command.this.timeout);
                    }
                    if (Command.this.finished) {
                        RootShell.log("Timeout Exception has occurred.");
                        Command.this.terminate("Timeout Exception");
                    }
                }
            }
        }
    }

    public void commandCompleted(int i, int i2) {
    }

    public void commandTerminated(int i, String str) {
    }

    public Command(int i, String... strArr) {
        this.command = strArr;
        this.id = i;
        createHandler(RootShell.handlerEnabled);
    }

    public Command(int i, boolean z, String... strArr) {
        this.command = strArr;
        this.id = i;
        createHandler(z);
    }

    public Command(int i, int i2, String... strArr) {
        this.command = strArr;
        this.id = i;
        this.timeout = i2;
        createHandler(RootShell.handlerEnabled);
    }

    public void commandOutput(int i, String str) {
        StringBuilder sb = new StringBuilder();
        sb.append("ID: ");
        sb.append(i);
        sb.append(", ");
        sb.append(str);
        RootShell.log("Command", sb.toString());
        this.totalOutputProcessed++;
    }

    /* access modifiers changed from: protected */
    public final void commandFinished() {
        if (!this.terminated) {
            synchronized (this) {
                if (this.mHandler == null || !this.handlerEnabled) {
                    commandCompleted(this.id, this.exitCode);
                } else {
                    Message obtainMessage = this.mHandler.obtainMessage();
                    Bundle bundle = new Bundle();
                    bundle.putInt(CommandHandler.ACTION, 2);
                    obtainMessage.setData(bundle);
                    this.mHandler.sendMessage(obtainMessage);
                }
                StringBuilder sb = new StringBuilder();
                sb.append("Command ");
                sb.append(this.id);
                sb.append(" finished.");
                RootShell.log(sb.toString());
                finishCommand();
            }
        }
    }

    private void createHandler(boolean z) {
        this.handlerEnabled = z;
        if (Looper.myLooper() == null || !z) {
            RootShell.log("CommandHandler not created");
            return;
        }
        RootShell.log("CommandHandler created");
        this.mHandler = new CommandHandler();
    }

    public final void finish() {
        RootShell.log("Command finished at users request!");
        commandFinished();
    }

    /* access modifiers changed from: protected */
    public final void finishCommand() {
        this.executing = false;
        this.finished = true;
        notifyAll();
    }

    public final String getCommand() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < this.command.length; i++) {
            if (i > 0) {
                sb.append(10);
            }
            sb.append(this.command[i]);
        }
        return sb.toString();
    }

    public final boolean isExecuting() {
        return this.executing;
    }

    public final boolean isHandlerEnabled() {
        return this.handlerEnabled;
    }

    public final boolean isFinished() {
        return this.finished;
    }

    public final int getExitCode() {
        return this.exitCode;
    }

    /* access modifiers changed from: protected */
    public final void setExitCode(int i) {
        synchronized (this) {
            this.exitCode = i;
        }
    }

    /* access modifiers changed from: protected */
    public final void startExecution() {
        this.executionMonitor = new ExecutionMonitor();
        this.executionMonitor.setPriority(1);
        this.executionMonitor.start();
        this.executing = true;
    }

    public final void terminate() {
        RootShell.log("Terminating command at users request!");
        terminated("Terminated at users request!");
    }

    /* access modifiers changed from: protected */
    public final void terminate(String str) {
        try {
            Shell.closeAll();
            RootShell.log("Terminating all shells.");
            terminated(str);
        } catch (IOException unused) {
        }
    }

    /* access modifiers changed from: protected */
    public final void terminated(String str) {
        synchronized (this) {
            if (this.mHandler == null || !this.handlerEnabled) {
                commandTerminated(this.id, str);
            } else {
                Message obtainMessage = this.mHandler.obtainMessage();
                Bundle bundle = new Bundle();
                bundle.putInt(CommandHandler.ACTION, 3);
                bundle.putString("text", str);
                obtainMessage.setData(bundle);
                this.mHandler.sendMessage(obtainMessage);
            }
            StringBuilder sb = new StringBuilder();
            sb.append("Command ");
            sb.append(this.id);
            sb.append(" did not finish because it was terminated. Termination reason: ");
            sb.append(str);
            RootShell.log(sb.toString());
            setExitCode(-1);
            this.terminated = true;
            finishCommand();
        }
    }

    /* access modifiers changed from: protected */
    public final void output(int i, String str) {
        this.totalOutput++;
        Handler handler = this.mHandler;
        if (handler == null || !this.handlerEnabled) {
            commandOutput(i, str);
            return;
        }
        Message obtainMessage = handler.obtainMessage();
        Bundle bundle = new Bundle();
        bundle.putInt(CommandHandler.ACTION, 1);
        bundle.putString("text", str);
        obtainMessage.setData(bundle);
        this.mHandler.sendMessage(obtainMessage);
    }

    public final void resetCommand() {
        this.finished = false;
        this.totalOutput = 0;
        this.totalOutputProcessed = 0;
        this.executing = false;
        this.terminated = false;
        this.exitCode = -1;
    }
}