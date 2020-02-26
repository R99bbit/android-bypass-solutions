package com.stericson.RootShell.execution;

import android.content.Context;
import android.os.Build.VERSION;
import com.kakao.network.ServerProtocol;
import com.stericson.RootShell.RootShell;
import com.stericson.RootShell.RootShell.LogLevel;
import com.stericson.RootShell.exceptions.RootDeniedException;
import java.io.BufferedReader;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.Writer;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.TimeoutException;
import org.acra.ACRAConstants;

public class Shell {
    private static Shell customShell = null;
    public static ShellContext defaultContext = ShellContext.NORMAL;
    private static Shell rootShell = null;
    private static Shell shell = null;
    private static String[] suVersion = {null, null};
    private static final String token = "F*D^W@#FGF";
    /* access modifiers changed from: private */
    public boolean close = false;
    /* access modifiers changed from: private */
    public final List<Command> commands = new ArrayList();
    /* access modifiers changed from: private */
    public String error = "";
    /* access modifiers changed from: private */
    public final BufferedReader errorStream;
    private Runnable input = new Runnable() {
        public void run() {
            while (true) {
                try {
                    synchronized (Shell.this.commands) {
                        while (!Shell.this.close && Shell.this.write >= Shell.this.commands.size()) {
                            Shell.this.isExecuting = false;
                            Shell.this.commands.wait();
                        }
                    }
                    if (Shell.this.write >= Shell.this.maxCommands) {
                        while (Shell.this.read != Shell.this.write) {
                            RootShell.log("Waiting for read and write to catch up before cleanup.");
                        }
                        Shell.this.cleanCommands();
                    }
                    if (Shell.this.write < Shell.this.commands.size()) {
                        Shell.this.isExecuting = true;
                        Command command = (Command) Shell.this.commands.get(Shell.this.write);
                        command.startExecution();
                        StringBuilder sb = new StringBuilder();
                        sb.append("Executing: ");
                        sb.append(command.getCommand());
                        sb.append(" with context: ");
                        sb.append(Shell.this.shellContext);
                        RootShell.log(sb.toString());
                        Shell.this.outputStream.write(command.getCommand());
                        StringBuilder sb2 = new StringBuilder();
                        sb2.append("\necho F*D^W@#FGF ");
                        sb2.append(Shell.this.totalExecuted);
                        sb2.append(" $?\n");
                        Shell.this.outputStream.write(sb2.toString());
                        Shell.this.outputStream.flush();
                        Shell.this.write = Shell.this.write + 1;
                        Shell.this.totalExecuted = Shell.this.totalExecuted + 1;
                    } else if (Shell.this.close) {
                        Shell.this.isExecuting = false;
                        Shell.this.outputStream.write("\nexit 0\n");
                        Shell.this.outputStream.flush();
                        RootShell.log("Closing shell");
                        Shell.this.write = 0;
                        Shell shell = Shell.this;
                        shell.closeQuietly((Writer) shell.outputStream);
                        return;
                    }
                } catch (IOException e) {
                    RootShell.log(e.getMessage(), LogLevel.ERROR, e);
                } catch (InterruptedException e2) {
                    try {
                        RootShell.log(e2.getMessage(), LogLevel.ERROR, e2);
                    } catch (Throwable th) {
                        Shell.this.write = 0;
                        Shell shell2 = Shell.this;
                        shell2.closeQuietly((Writer) shell2.outputStream);
                        throw th;
                    }
                }
            }
            while (true) {
            }
            Shell.this.write = 0;
            Shell shell3 = Shell.this;
            shell3.closeQuietly((Writer) shell3.outputStream);
        }
    };
    /* access modifiers changed from: private */
    public final BufferedReader inputStream;
    private boolean isCleaning = false;
    public boolean isClosed = false;
    public boolean isExecuting = false;
    public boolean isReading = false;
    private Boolean isSELinuxEnforcing = null;
    /* access modifiers changed from: private */
    public int maxCommands = ACRAConstants.DEFAULT_SOCKET_TIMEOUT;
    private Runnable output = new Runnable() {
        /* JADX WARNING: Code restructure failed: missing block: B:19:?, code lost:
            com.stericson.RootShell.execution.Shell.access$1300(r9.this$0).waitFor();
            com.stericson.RootShell.execution.Shell.access$1300(r9.this$0).destroy();
         */
        /* JADX WARNING: Code restructure failed: missing block: B:22:0x007d, code lost:
            if (com.stericson.RootShell.execution.Shell.access$500(r9.this$0) < com.stericson.RootShell.execution.Shell.access$100(r9.this$0).size()) goto L_0x007f;
         */
        /* JADX WARNING: Code restructure failed: missing block: B:23:0x007f, code lost:
            if (r1 == null) goto L_0x0081;
         */
        /* JADX WARNING: Code restructure failed: missing block: B:24:0x0081, code lost:
            r1 = (com.stericson.RootShell.execution.Command) com.stericson.RootShell.execution.Shell.access$100(r9.this$0).get(com.stericson.RootShell.execution.Shell.access$500(r9.this$0));
         */
        /* JADX WARNING: Code restructure failed: missing block: B:26:0x0097, code lost:
            if (r1.totalOutput < r1.totalOutputProcessed) goto L_0x0099;
         */
        /* JADX WARNING: Code restructure failed: missing block: B:27:0x0099, code lost:
            r1.terminated("All output not processed!");
            r1.terminated("Did you forget the super.commandOutput call or are you waiting on the command object?");
         */
        /* JADX WARNING: Code restructure failed: missing block: B:28:0x00a4, code lost:
            r1.terminated("Unexpected Termination.");
         */
        /* JADX WARNING: Code restructure failed: missing block: B:29:0x00a9, code lost:
            com.stericson.RootShell.execution.Shell.access$508(r9.this$0);
            r1 = null;
         */
        /* JADX WARNING: Code restructure failed: missing block: B:30:0x00b0, code lost:
            com.stericson.RootShell.execution.Shell.access$502(r9.this$0, 0);
         */
        /* JADX WARNING: Code restructure failed: missing block: B:51:0x010d, code lost:
            r9.this$0.processErrors(r1);
            r4 = 0;
         */
        /* JADX WARNING: Code restructure failed: missing block: B:53:0x0117, code lost:
            if (r1.totalOutput <= r1.totalOutputProcessed) goto L_0x0151;
         */
        /* JADX WARNING: Code restructure failed: missing block: B:54:0x0119, code lost:
            if (r4 != 0) goto L_0x013d;
         */
        /* JADX WARNING: Code restructure failed: missing block: B:55:0x011b, code lost:
            r4 = r4 + 1;
            r5 = new java.lang.StringBuilder();
            r5.append("Waiting for output to be processed. ");
            r5.append(r1.totalOutputProcessed);
            r5.append(" Of ");
            r5.append(r1.totalOutput);
            com.stericson.RootShell.RootShell.log(r5.toString());
         */
        /* JADX WARNING: Code restructure failed: missing block: B:57:?, code lost:
            monitor-enter(r9);
         */
        /* JADX WARNING: Code restructure failed: missing block: B:60:?, code lost:
            wait(2000);
         */
        /* JADX WARNING: Code restructure failed: missing block: B:61:0x0143, code lost:
            monitor-exit(r9);
         */
        /* JADX WARNING: Code restructure failed: missing block: B:67:0x0148, code lost:
            r5 = move-exception;
         */
        /* JADX WARNING: Code restructure failed: missing block: B:69:?, code lost:
            com.stericson.RootShell.RootShell.log(r5.getMessage());
         */
        /* JADX WARNING: Exception block dominator not found, dom blocks: [] */
        /* JADX WARNING: Failed to process nested try/catch */
        /* JADX WARNING: Missing exception handler attribute for start block: B:20:0x006d */
        /* JADX WARNING: Missing exception handler attribute for start block: B:48:0x0105 */
        /* JADX WARNING: Removed duplicated region for block: B:81:0x010d A[EDGE_INSN: B:81:0x010d->B:51:0x010d ?: BREAK  
        EDGE_INSN: B:81:0x010d->B:51:0x010d ?: BREAK  , SYNTHETIC] */
        /* JADX WARNING: Removed duplicated region for block: B:86:0x0002 A[SYNTHETIC] */
        public void run() {
            int i;
            int i2;
            loop0:
            while (true) {
                Command command = null;
                while (true) {
                    if (!Shell.this.close || Shell.this.inputStream.ready() || Shell.this.read < Shell.this.commands.size()) {
                        Shell.this.isReading = false;
                        String readLine = Shell.this.inputStream.readLine();
                        Shell.this.isReading = true;
                        if (readLine == null) {
                            break loop0;
                        }
                        if (command == null) {
                            if (Shell.this.read < Shell.this.commands.size()) {
                                command = (Command) Shell.this.commands.get(Shell.this.read);
                            } else if (!Shell.this.close) {
                            }
                        }
                        int indexOf = readLine.indexOf(Shell.token);
                        i = -1;
                        if (indexOf == -1) {
                            command.output(command.id, readLine);
                        } else if (indexOf > 0) {
                            command.output(command.id, readLine.substring(0, indexOf));
                        }
                        if (indexOf >= 0) {
                            String[] split = readLine.substring(indexOf).split(ServerProtocol.AUTHORIZATION_HEADER_DELIMITER);
                            if (split.length >= 2 && split[1] != null) {
                                try {
                                    i2 = Integer.parseInt(split[1]);
                                } catch (NumberFormatException unused) {
                                    i2 = 0;
                                }
                                i = Integer.parseInt(split[2]);
                                try {
                                    if (i2 != Shell.this.totalRead) {
                                        break;
                                    }
                                } catch (IOException e) {
                                    RootShell.log(e.getMessage(), LogLevel.ERROR, e);
                                } catch (Throwable th) {
                                    Shell shell = Shell.this;
                                    shell.closeQuietly((Writer) shell.outputStream);
                                    Shell shell2 = Shell.this;
                                    shell2.closeQuietly((Reader) shell2.errorStream);
                                    Shell shell3 = Shell.this;
                                    shell3.closeQuietly((Reader) shell3.inputStream);
                                    RootShell.log("Shell destroyed");
                                    Shell shell4 = Shell.this;
                                    shell4.isClosed = true;
                                    shell4.isReading = false;
                                    throw th;
                                }
                            }
                        } else {
                            continue;
                        }
                    }
                }
                RootShell.log("Read all output");
                command.setExitCode(i);
                command.commandFinished();
                Shell.this.read = Shell.this.read + 1;
                Shell.this.totalRead = Shell.this.totalRead + 1;
            }
            Shell shell5 = Shell.this;
            shell5.closeQuietly((Writer) shell5.outputStream);
            Shell shell6 = Shell.this;
            shell6.closeQuietly((Reader) shell6.errorStream);
            Shell shell7 = Shell.this;
            shell7.closeQuietly((Reader) shell7.inputStream);
            RootShell.log("Shell destroyed");
            Shell shell8 = Shell.this;
            shell8.isClosed = true;
            shell8.isReading = false;
        }
    };
    /* access modifiers changed from: private */
    public final OutputStreamWriter outputStream;
    /* access modifiers changed from: private */
    public final Process proc;
    /* access modifiers changed from: private */
    public int read = 0;
    /* access modifiers changed from: private */
    public ShellContext shellContext = ShellContext.NORMAL;
    private int shellTimeout = 25000;
    private ShellType shellType = null;
    /* access modifiers changed from: private */
    public int totalExecuted = 0;
    /* access modifiers changed from: private */
    public int totalRead = 0;
    /* access modifiers changed from: private */
    public int write = 0;

    public enum ShellContext {
        NORMAL("normal"),
        SHELL("u:r:shell:s0"),
        SYSTEM_SERVER("u:r:system_server:s0"),
        SYSTEM_APP("u:r:system_app:s0"),
        PLATFORM_APP("u:r:platform_app:s0"),
        UNTRUSTED_APP("u:r:untrusted_app:s0"),
        RECOVERY("u:r:recovery:s0");
        
        private String value;

        private ShellContext(String str) {
            this.value = str;
        }

        public String getValue() {
            return this.value;
        }
    }

    public enum ShellType {
        NORMAL,
        ROOT,
        CUSTOM
    }

    protected static class Worker extends Thread {
        public int exit;
        public Shell shell;

        private Worker(Shell shell2) {
            this.exit = -911;
            this.shell = shell2;
        }

        public void run() {
            try {
                this.shell.outputStream.write("echo Started\n");
                this.shell.outputStream.flush();
                while (true) {
                    String readLine = this.shell.inputStream.readLine();
                    if (readLine == null) {
                        throw new EOFException();
                    } else if (!"".equals(readLine)) {
                        if ("Started".equals(readLine)) {
                            this.exit = 1;
                            setShellOom();
                            return;
                        }
                        this.shell.error = "unkown error occured.";
                    }
                }
            } catch (IOException e) {
                this.exit = -42;
                if (e.getMessage() != null) {
                    this.shell.error = e.getMessage();
                } else {
                    this.shell.error = "RootAccess denied?.";
                }
            }
        }

        private void setShellOom() {
            Field field;
            try {
                Class<?> cls = this.shell.proc.getClass();
                try {
                    field = cls.getDeclaredField("pid");
                } catch (NoSuchFieldException unused) {
                    field = cls.getDeclaredField("id");
                }
                field.setAccessible(true);
                int intValue = ((Integer) field.get(this.shell.proc)).intValue();
                OutputStreamWriter access$800 = this.shell.outputStream;
                StringBuilder sb = new StringBuilder();
                sb.append("(echo -17 > /proc/");
                sb.append(intValue);
                sb.append("/oom_adj) &> /dev/null\n");
                access$800.write(sb.toString());
                this.shell.outputStream.write("(echo -17 > /proc/$$/oom_adj) &> /dev/null\n");
                this.shell.outputStream.flush();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    /* JADX WARNING: Can't wrap try/catch for region: R(5:25|26|27|28|29) */
    /* JADX WARNING: Can't wrap try/catch for region: R(5:30|31|32|33|34) */
    /* JADX WARNING: Missing exception handler attribute for start block: B:27:0x01a0 */
    /* JADX WARNING: Missing exception handler attribute for start block: B:32:0x01bc */
    /* JADX WARNING: Unknown top exception splitter block from list: {B:27:0x01a0=Splitter:B:27:0x01a0, B:32:0x01bc=Splitter:B:32:0x01bc} */
    private Shell(String str, ShellType shellType2, ShellContext shellContext2, int i) throws IOException, TimeoutException, RootDeniedException {
        StringBuilder sb = new StringBuilder();
        sb.append("Starting shell: ");
        sb.append(str);
        RootShell.log(sb.toString());
        StringBuilder sb2 = new StringBuilder();
        sb2.append("Context: ");
        sb2.append(shellContext2.getValue());
        RootShell.log(sb2.toString());
        StringBuilder sb3 = new StringBuilder();
        sb3.append("Timeout: ");
        sb3.append(i);
        RootShell.log(sb3.toString());
        this.shellType = shellType2;
        this.shellTimeout = i <= 0 ? this.shellTimeout : i;
        this.shellContext = shellContext2;
        if (this.shellContext == ShellContext.NORMAL) {
            this.proc = Runtime.getRuntime().exec(str);
        } else {
            String suVersion2 = getSuVersion(false);
            String suVersion3 = getSuVersion(true);
            if (!isSELinuxEnforcing() || suVersion2 == null || suVersion3 == null || !suVersion2.endsWith("SUPERSU") || Integer.valueOf(suVersion3).intValue() < 190) {
                RootShell.log("Su binary --context switch not supported!");
                StringBuilder sb4 = new StringBuilder();
                sb4.append("Su binary display version: ");
                sb4.append(suVersion2);
                RootShell.log(sb4.toString());
                StringBuilder sb5 = new StringBuilder();
                sb5.append("Su binary internal version: ");
                sb5.append(suVersion3);
                RootShell.log(sb5.toString());
                StringBuilder sb6 = new StringBuilder();
                sb6.append("SELinuxEnforcing: ");
                sb6.append(isSELinuxEnforcing());
                RootShell.log(sb6.toString());
            } else {
                StringBuilder sb7 = new StringBuilder();
                sb7.append(str);
                sb7.append(" --context ");
                sb7.append(this.shellContext.getValue());
                str = sb7.toString();
            }
            this.proc = Runtime.getRuntime().exec(str);
        }
        this.inputStream = new BufferedReader(new InputStreamReader(this.proc.getInputStream(), "UTF-8"));
        this.errorStream = new BufferedReader(new InputStreamReader(this.proc.getErrorStream(), "UTF-8"));
        this.outputStream = new OutputStreamWriter(this.proc.getOutputStream(), "UTF-8");
        Worker worker = new Worker();
        worker.start();
        try {
            worker.join((long) this.shellTimeout);
            if (worker.exit == -911) {
                this.proc.destroy();
                closeQuietly((Reader) this.inputStream);
                closeQuietly((Reader) this.errorStream);
                closeQuietly((Writer) this.outputStream);
                throw new TimeoutException(this.error);
            } else if (worker.exit != -42) {
                Thread thread = new Thread(this.input, "Shell Input");
                thread.setPriority(5);
                thread.start();
                Thread thread2 = new Thread(this.output, "Shell Output");
                thread2.setPriority(5);
                thread2.start();
            } else {
                this.proc.destroy();
                closeQuietly((Reader) this.inputStream);
                closeQuietly((Reader) this.errorStream);
                closeQuietly((Writer) this.outputStream);
                throw new RootDeniedException("Root Access Denied");
            }
        } catch (InterruptedException unused) {
            worker.interrupt();
            Thread.currentThread().interrupt();
            throw new TimeoutException();
        }
    }

    public Command add(Command command) throws IOException {
        if (!this.close) {
            do {
            } while (this.isCleaning);
            command.resetCommand();
            this.commands.add(command);
            notifyThreads();
            return command;
        }
        throw new IllegalStateException("Unable to add commands to a closed shell");
    }

    public final void useCWD(Context context) throws IOException, TimeoutException, RootDeniedException {
        StringBuilder sb = new StringBuilder();
        sb.append("cd ");
        sb.append(context.getApplicationInfo().dataDir);
        add(new Command(-1, false, sb.toString()));
    }

    /* access modifiers changed from: private */
    public void cleanCommands() {
        this.isCleaning = true;
        int i = this.maxCommands;
        int abs = Math.abs(i - (i / 4));
        StringBuilder sb = new StringBuilder();
        sb.append("Cleaning up: ");
        sb.append(abs);
        RootShell.log(sb.toString());
        for (int i2 = 0; i2 < abs; i2++) {
            this.commands.remove(0);
        }
        this.read = this.commands.size() - 1;
        this.write = this.commands.size() - 1;
        this.isCleaning = false;
    }

    /* access modifiers changed from: private */
    public void closeQuietly(Reader reader) {
        if (reader != null) {
            try {
                reader.close();
            } catch (Exception unused) {
            }
        }
    }

    /* access modifiers changed from: private */
    public void closeQuietly(Writer writer) {
        if (writer != null) {
            try {
                writer.close();
            } catch (Exception unused) {
            }
        }
    }

    public void close() throws IOException {
        RootShell.log("Request to close shell!");
        int i = 0;
        while (this.isExecuting) {
            RootShell.log("Waiting on shell to finish executing before closing...");
            i++;
            if (i > 10000) {
                break;
            }
        }
        synchronized (this.commands) {
            this.close = true;
            notifyThreads();
        }
        RootShell.log("Shell Closed!");
        if (this == rootShell) {
            rootShell = null;
        } else if (this == shell) {
            shell = null;
        } else if (this == customShell) {
            customShell = null;
        }
    }

    public static void closeCustomShell() throws IOException {
        RootShell.log("Request to close custom shell!");
        Shell shell2 = customShell;
        if (shell2 != null) {
            shell2.close();
        }
    }

    public static void closeRootShell() throws IOException {
        RootShell.log("Request to close root shell!");
        Shell shell2 = rootShell;
        if (shell2 != null) {
            shell2.close();
        }
    }

    public static void closeShell() throws IOException {
        RootShell.log("Request to close normal shell!");
        Shell shell2 = shell;
        if (shell2 != null) {
            shell2.close();
        }
    }

    public static void closeAll() throws IOException {
        RootShell.log("Request to close all shells!");
        closeShell();
        closeRootShell();
        closeCustomShell();
    }

    public int getCommandQueuePosition(Command command) {
        return this.commands.indexOf(command);
    }

    public String getCommandQueuePositionString(Command command) {
        StringBuilder sb = new StringBuilder();
        sb.append("Command is in position ");
        sb.append(getCommandQueuePosition(command));
        sb.append(" currently executing command at position ");
        sb.append(this.write);
        sb.append(" and the number of commands is ");
        sb.append(this.commands.size());
        return sb.toString();
    }

    public static Shell getOpenShell() {
        Shell shell2 = customShell;
        if (shell2 != null) {
            return shell2;
        }
        Shell shell3 = rootShell;
        if (shell3 != null) {
            return shell3;
        }
        return shell;
    }

    /* JADX WARNING: Can't wrap try/catch for region: R(11:16|17|(1:19)|20|21|22|23|(3:24|(2:27|(2:29|(1:55)(2:56|53))(3:31|32|(1:54)(2:57|53)))(0)|35)|34|35|36) */
    /* JADX WARNING: Exception block dominator not found, dom blocks: [] */
    /* JADX WARNING: Missing exception handler attribute for start block: B:20:0x003c */
    /* JADX WARNING: Missing exception handler attribute for start block: B:22:0x003f */
    /* JADX WARNING: Removed duplicated region for block: B:27:0x004c A[Catch:{ IOException -> 0x006f, InterruptedException -> 0x0069 }] */
    private synchronized String getSuVersion(boolean z) {
        char c;
        String str;
        c = z ? (char) 0 : 1;
        if (suVersion[c] == null) {
            String str2 = null;
            try {
                Process exec = Runtime.getRuntime().exec(z ? "su -V" : "su -v", null);
                exec.waitFor();
                ArrayList arrayList = new ArrayList();
                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(exec.getInputStream()));
                while (true) {
                    String readLine = bufferedReader.readLine();
                    if (readLine != null) {
                        arrayList.add(readLine);
                    }
                    bufferedReader.close();
                    exec.destroy();
                    Iterator it = arrayList.iterator();
                    while (true) {
                        if (it.hasNext()) {
                            str = (String) it.next();
                            if (z) {
                                try {
                                    if (Integer.parseInt(str) > 0) {
                                        break;
                                    }
                                } catch (NumberFormatException unused) {
                                    continue;
                                }
                            } else if (str.contains(".")) {
                                break;
                            }
                        }
                    }
                    str2 = str;
                    suVersion[c] = str2;
                    break;
                }
            } catch (IOException e) {
                e.printStackTrace();
                return null;
            } catch (InterruptedException e2) {
                e2.printStackTrace();
                return null;
            }
        }
        return suVersion[c];
    }

    public static boolean isShellOpen() {
        return shell == null;
    }

    public static boolean isCustomShellOpen() {
        return customShell == null;
    }

    public static boolean isRootShellOpen() {
        return rootShell == null;
    }

    public static boolean isAnyShellOpen() {
        return (shell == null && rootShell == null && customShell == null) ? false : true;
    }

    public synchronized boolean isSELinuxEnforcing() {
        FileInputStream fileInputStream;
        if (this.isSELinuxEnforcing == null) {
            Boolean bool = null;
            if (VERSION.SDK_INT >= 17) {
                boolean z = true;
                if (new File("/sys/fs/selinux/enforce").exists()) {
                    try {
                        fileInputStream = new FileInputStream("/sys/fs/selinux/enforce");
                        bool = Boolean.valueOf(fileInputStream.read() == 49);
                        fileInputStream.close();
                    } catch (Exception unused) {
                    } catch (Throwable th) {
                        fileInputStream.close();
                        throw th;
                    }
                }
                if (bool == null) {
                    if (VERSION.SDK_INT < 19) {
                        z = false;
                    }
                    bool = Boolean.valueOf(z);
                }
            }
            if (bool == null) {
                bool = Boolean.valueOf(false);
            }
            this.isSELinuxEnforcing = bool;
        }
        return this.isSELinuxEnforcing.booleanValue();
    }

    /* access modifiers changed from: protected */
    public void notifyThreads() {
        new Thread() {
            public void run() {
                synchronized (Shell.this.commands) {
                    Shell.this.commands.notifyAll();
                }
            }
        }.start();
    }

    public void processErrors(Command command) {
        while (this.errorStream.ready() && command != null) {
            try {
                String readLine = this.errorStream.readLine();
                if (readLine != null) {
                    command.output(command.id, readLine);
                } else {
                    return;
                }
            } catch (Exception e) {
                RootShell.log(e.getMessage(), LogLevel.ERROR, e);
                return;
            }
        }
    }

    public static void runRootCommand(Command command) throws IOException, TimeoutException, RootDeniedException {
        startRootShell().add(command);
    }

    public static void runCommand(Command command) throws IOException, TimeoutException {
        startShell().add(command);
    }

    public static Shell startRootShell() throws IOException, TimeoutException, RootDeniedException {
        return startRootShell(0, 3);
    }

    public static Shell startRootShell(int i) throws IOException, TimeoutException, RootDeniedException {
        return startRootShell(i, 3);
    }

    public static Shell startRootShell(int i, int i2) throws IOException, TimeoutException, RootDeniedException {
        return startRootShell(i, defaultContext, i2);
    }

    /* JADX WARNING: Code restructure failed: missing block: B:20:0x004b, code lost:
        r1 = r3;
     */
    public static Shell startRootShell(int i, ShellContext shellContext2, int i2) throws IOException, TimeoutException, RootDeniedException {
        int i3;
        Shell shell2 = rootShell;
        if (shell2 == null) {
            RootShell.log("Starting Root Shell!");
            int i4 = 0;
            while (rootShell == null) {
                try {
                    StringBuilder sb = new StringBuilder();
                    sb.append("Trying to open Root Shell, attempt #");
                    sb.append(i4);
                    RootShell.log(sb.toString());
                    rootShell = new Shell("su", ShellType.ROOT, shellContext2, i);
                } catch (IOException e) {
                    i3 = i4 + 1;
                    if (i4 >= i2) {
                        RootShell.log("IOException, could not start shell");
                        throw e;
                    }
                } catch (RootDeniedException e2) {
                    i3 = i4 + 1;
                    if (i4 >= i2) {
                        RootShell.log("RootDeniedException, could not start shell");
                        throw e2;
                    }
                } catch (TimeoutException e3) {
                    i3 = i4 + 1;
                    if (i4 >= i2) {
                        RootShell.log("TimeoutException, could not start shell");
                        throw e3;
                    }
                }
            }
        } else if (shell2.shellContext != shellContext2) {
            try {
                StringBuilder sb2 = new StringBuilder();
                sb2.append("Context is different than open shell, switching context... ");
                sb2.append(rootShell.shellContext);
                sb2.append(" VS ");
                sb2.append(shellContext2);
                RootShell.log(sb2.toString());
                rootShell.switchRootShellContext(shellContext2);
            } catch (IOException e4) {
                if (i2 <= 0) {
                    RootShell.log("IOException, could not switch context!");
                    throw e4;
                }
            } catch (RootDeniedException e5) {
                if (i2 <= 0) {
                    RootShell.log("RootDeniedException, could not switch context!");
                    throw e5;
                }
            } catch (TimeoutException e6) {
                if (i2 <= 0) {
                    RootShell.log("TimeoutException, could not switch context!");
                    throw e6;
                }
            }
        } else {
            RootShell.log("Using Existing Root Shell!");
        }
        return rootShell;
    }

    public static Shell startCustomShell(String str) throws IOException, TimeoutException, RootDeniedException {
        return startCustomShell(str, 0);
    }

    public static Shell startCustomShell(String str, int i) throws IOException, TimeoutException, RootDeniedException {
        if (customShell == null) {
            RootShell.log("Starting Custom Shell!");
            customShell = new Shell(str, ShellType.CUSTOM, ShellContext.NORMAL, i);
        } else {
            RootShell.log("Using Existing Custom Shell!");
        }
        return customShell;
    }

    public static Shell startShell() throws IOException, TimeoutException {
        return startShell(0);
    }

    public static Shell startShell(int i) throws IOException, TimeoutException {
        try {
            if (shell == null) {
                RootShell.log("Starting Shell!");
                shell = new Shell("/system/bin/sh", ShellType.NORMAL, ShellContext.NORMAL, i);
            } else {
                RootShell.log("Using Existing Shell!");
            }
            return shell;
        } catch (RootDeniedException unused) {
            throw new IOException();
        }
    }

    public Shell switchRootShellContext(ShellContext shellContext2) throws IOException, TimeoutException, RootDeniedException {
        if (this.shellType == ShellType.ROOT) {
            try {
                closeRootShell();
            } catch (Exception unused) {
                RootShell.log("Problem closing shell while trying to switch context...");
            }
            return startRootShell(this.shellTimeout, shellContext2, 3);
        }
        RootShell.log("Can only switch context on a root shell!");
        return this;
    }
}