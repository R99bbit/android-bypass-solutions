package com.stericson.RootShell;

import android.util.Log;
import com.kakao.network.ServerProtocol;
import com.stericson.RootShell.exceptions.RootDeniedException;
import com.stericson.RootShell.execution.Command;
import com.stericson.RootShell.execution.Shell;
import com.stericson.RootShell.execution.Shell.ShellContext;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.concurrent.TimeoutException;

public class RootShell {
    public static boolean debugMode = false;
    public static int defaultCommandTimeout = 20000;
    public static boolean handlerEnabled = true;
    public static final String version = "RootShell v1.3";

    /* renamed from: com.stericson.RootShell.RootShell$4 reason: invalid class name */
    static /* synthetic */ class AnonymousClass4 {
        static final /* synthetic */ int[] $SwitchMap$com$stericson$RootShell$RootShell$LogLevel = new int[LogLevel.values().length];

        /* JADX WARNING: Can't wrap try/catch for region: R(10:0|1|2|3|4|5|6|7|8|10) */
        /* JADX WARNING: Can't wrap try/catch for region: R(8:0|1|2|3|4|5|6|(3:7|8|10)) */
        /* JADX WARNING: Failed to process nested try/catch */
        /* JADX WARNING: Missing exception handler attribute for start block: B:3:0x0014 */
        /* JADX WARNING: Missing exception handler attribute for start block: B:5:0x001f */
        /* JADX WARNING: Missing exception handler attribute for start block: B:7:0x002a */
        static {
            $SwitchMap$com$stericson$RootShell$RootShell$LogLevel[LogLevel.VERBOSE.ordinal()] = 1;
            $SwitchMap$com$stericson$RootShell$RootShell$LogLevel[LogLevel.ERROR.ordinal()] = 2;
            $SwitchMap$com$stericson$RootShell$RootShell$LogLevel[LogLevel.DEBUG.ordinal()] = 3;
            try {
                $SwitchMap$com$stericson$RootShell$RootShell$LogLevel[LogLevel.WARN.ordinal()] = 4;
            } catch (NoSuchFieldError unused) {
            }
        }
    }

    public enum LogLevel {
        VERBOSE,
        ERROR,
        DEBUG,
        WARN
    }

    public static void closeAllShells() throws IOException {
        Shell.closeAll();
    }

    public static void closeCustomShell() throws IOException {
        Shell.closeCustomShell();
    }

    public static void closeShell(boolean z) throws IOException {
        if (z) {
            Shell.closeRootShell();
        } else {
            Shell.closeShell();
        }
    }

    public static boolean exists(String str) {
        return exists(str, false);
    }

    /* JADX WARNING: No exception handlers in catch block: Catch:{  } */
    public static boolean exists(String str, boolean z) {
        final ArrayList<String> arrayList = new ArrayList<>();
        StringBuilder sb = new StringBuilder();
        sb.append("ls ");
        sb.append(z ? "-d " : ServerProtocol.AUTHORIZATION_HEADER_DELIMITER);
        String sb2 = sb.toString();
        StringBuilder sb3 = new StringBuilder();
        sb3.append(sb2);
        sb3.append(str);
        AnonymousClass1 r1 = new Command(0, false, new String[]{sb3.toString()}) {
            public void commandOutput(int i, String str) {
                RootShell.log(str);
                arrayList.add(str);
                super.commandOutput(i, str);
            }
        };
        try {
            getShell(false).add(r1);
            commandWait(getShell(false), r1);
            for (String trim : arrayList) {
                if (trim.trim().equals(str)) {
                    return true;
                }
            }
            arrayList.clear();
            getShell(true).add(r1);
            commandWait(getShell(true), r1);
            ArrayList<String> arrayList2 = new ArrayList<>();
            arrayList2.addAll(arrayList);
            for (String trim2 : arrayList2) {
                if (trim2.trim().equals(str)) {
                    return true;
                }
            }
        } catch (Exception unused) {
        }
        return false;
    }

    public static List<String> findBinary(String str) {
        return findBinary(str, null);
    }

    public static List<String> findBinary(String str, List<String> list) {
        ArrayList arrayList = new ArrayList();
        if (list == null) {
            list = getPath();
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Checking for ");
        sb.append(str);
        log(sb.toString());
        boolean z = false;
        try {
            for (String next : list) {
                if (!next.endsWith("/")) {
                    StringBuilder sb2 = new StringBuilder();
                    sb2.append(next);
                    sb2.append("/");
                    next = sb2.toString();
                }
                final String str2 = next;
                StringBuilder sb3 = new StringBuilder();
                sb3.append("stat ");
                sb3.append(str2);
                sb3.append(str);
                String[] strArr = {sb3.toString()};
                final String str3 = str;
                final ArrayList arrayList2 = arrayList;
                AnonymousClass2 r1 = new Command(0, false, strArr) {
                    public void commandOutput(int i, String str) {
                        if (str.contains("File: ") && str.contains(str3)) {
                            arrayList2.add(str2);
                            StringBuilder sb = new StringBuilder();
                            sb.append(str3);
                            sb.append(" was found here: ");
                            sb.append(str2);
                            RootShell.log(sb.toString());
                        }
                        RootShell.log(str);
                        super.commandOutput(i, str);
                    }
                };
                getShell(false).add(r1);
                commandWait(getShell(false), r1);
            }
            z = !arrayList.isEmpty();
        } catch (Exception unused) {
            StringBuilder sb4 = new StringBuilder();
            sb4.append(str);
            sb4.append(" was not found, more information MAY be available with Debugging on.");
            log(sb4.toString());
        }
        if (!z) {
            log("Trying second method");
            for (String next2 : list) {
                if (!next2.endsWith("/")) {
                    StringBuilder sb5 = new StringBuilder();
                    sb5.append(next2);
                    sb5.append("/");
                    next2 = sb5.toString();
                }
                StringBuilder sb6 = new StringBuilder();
                sb6.append(next2);
                sb6.append(str);
                if (exists(sb6.toString())) {
                    StringBuilder sb7 = new StringBuilder();
                    sb7.append(str);
                    sb7.append(" was found here: ");
                    sb7.append(next2);
                    log(sb7.toString());
                    arrayList.add(next2);
                } else {
                    StringBuilder sb8 = new StringBuilder();
                    sb8.append(str);
                    sb8.append(" was NOT found here: ");
                    sb8.append(next2);
                    log(sb8.toString());
                }
            }
        }
        Collections.reverse(arrayList);
        return arrayList;
    }

    public static Shell getCustomShell(String str, int i) throws IOException, TimeoutException, RootDeniedException {
        return getCustomShell(str, i);
    }

    public static List<String> getPath() {
        return Arrays.asList(System.getenv("PATH").split(":"));
    }

    public static Shell getShell(boolean z, int i, ShellContext shellContext, int i2) throws IOException, TimeoutException, RootDeniedException {
        if (z) {
            return Shell.startRootShell(i, shellContext, i2);
        }
        return Shell.startShell(i);
    }

    public static Shell getShell(boolean z, int i, ShellContext shellContext) throws IOException, TimeoutException, RootDeniedException {
        return getShell(z, i, shellContext, 3);
    }

    public static Shell getShell(boolean z, ShellContext shellContext) throws IOException, TimeoutException, RootDeniedException {
        return getShell(z, 0, shellContext, 3);
    }

    public static Shell getShell(boolean z, int i) throws IOException, TimeoutException, RootDeniedException {
        return getShell(z, i, Shell.defaultContext, 3);
    }

    public static Shell getShell(boolean z) throws IOException, TimeoutException, RootDeniedException {
        return getShell(z, 0);
    }

    public static boolean isAccessGiven() {
        final HashSet<String> hashSet = new HashSet<>();
        try {
            log("Checking for Root access");
            AnonymousClass3 r2 = new Command(158, false, new String[]{"id"}) {
                public void commandOutput(int i, String str) {
                    if (i == 158) {
                        hashSet.addAll(Arrays.asList(str.split(ServerProtocol.AUTHORIZATION_HEADER_DELIMITER)));
                    }
                    super.commandOutput(i, str);
                }
            };
            Shell.startRootShell().add(r2);
            commandWait(Shell.startRootShell(), r2);
            for (String str : hashSet) {
                log(str);
                if (str.toLowerCase().contains("uid=0")) {
                    log("Access Given");
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public static boolean isBusyboxAvailable() {
        return findBinary("busybox").size() > 0;
    }

    public static boolean isRootAvailable() {
        return findBinary("su").size() > 0;
    }

    public static void log(String str) {
        log(null, str, LogLevel.DEBUG, null);
    }

    public static void log(String str, String str2) {
        log(str, str2, LogLevel.DEBUG, null);
    }

    public static void log(String str, LogLevel logLevel, Exception exc) {
        log(null, str, logLevel, exc);
    }

    public static boolean islog() {
        return debugMode;
    }

    public static void log(String str, String str2, LogLevel logLevel, Exception exc) {
        if (str2 != null && !str2.equals("") && debugMode) {
            if (str == null) {
                str = version;
            }
            int i = AnonymousClass4.$SwitchMap$com$stericson$RootShell$RootShell$LogLevel[logLevel.ordinal()];
            if (i == 1) {
                Log.v(str, str2);
            } else if (i == 2) {
                Log.e(str, str2, exc);
            } else if (i == 3) {
                Log.d(str, str2);
            } else if (i == 4) {
                Log.w(str, str2);
            }
        }
    }

    private static void commandWait(Shell shell, Command command) throws Exception {
        while (!command.isFinished()) {
            log(version, shell.getCommandQueuePositionString(command));
            StringBuilder sb = new StringBuilder();
            sb.append("Processed ");
            sb.append(command.totalOutputProcessed);
            sb.append(" of ");
            sb.append(command.totalOutput);
            sb.append(" output from command.");
            log(version, sb.toString());
            synchronized (command) {
                try {
                    if (!command.isFinished()) {
                        command.wait(2000);
                    }
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
            if (!command.isExecuting() && !command.isFinished()) {
                if (!shell.isExecuting && !shell.isReading) {
                    StringBuilder sb2 = new StringBuilder();
                    sb2.append("Waiting for a command to be executed in a shell that is not executing and not reading! \n\n Command: ");
                    sb2.append(command.getCommand());
                    log(version, sb2.toString());
                    Exception exc = new Exception();
                    exc.setStackTrace(Thread.currentThread().getStackTrace());
                    exc.printStackTrace();
                } else if (!shell.isExecuting || shell.isReading) {
                    StringBuilder sb3 = new StringBuilder();
                    sb3.append("Waiting for a command to be executed in a shell that is not reading! \n\n Command: ");
                    sb3.append(command.getCommand());
                    log(version, sb3.toString());
                    Exception exc2 = new Exception();
                    exc2.setStackTrace(Thread.currentThread().getStackTrace());
                    exc2.printStackTrace();
                } else {
                    StringBuilder sb4 = new StringBuilder();
                    sb4.append("Waiting for a command to be executed in a shell that is executing but not reading! \n\n Command: ");
                    sb4.append(command.getCommand());
                    log(version, sb4.toString());
                    Exception exc3 = new Exception();
                    exc3.setStackTrace(Thread.currentThread().getStackTrace());
                    exc3.printStackTrace();
                }
            }
        }
    }
}