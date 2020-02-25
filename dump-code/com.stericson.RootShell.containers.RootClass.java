package com.stericson.RootShell.containers;

import com.embrain.panelpower.IConstValue;
import com.kakao.network.ServerProtocol;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileFilter;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RootClass {
    static String PATH_TO_DX = "/Users/Chris/Projects/android-sdk-macosx/build-tools/18.0.1/dx";

    /* renamed from: com.stericson.RootShell.containers.RootClass$1 reason: invalid class name */
    static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$com$stericson$RootShell$containers$RootClass$READ_STATE = new int[READ_STATE.values().length];

        /* JADX WARNING: Can't wrap try/catch for region: R(6:0|1|2|3|4|6) */
        /* JADX WARNING: Code restructure failed: missing block: B:7:?, code lost:
            return;
         */
        /* JADX WARNING: Failed to process nested try/catch */
        /* JADX WARNING: Missing exception handler attribute for start block: B:3:0x0014 */
        static {
            $SwitchMap$com$stericson$RootShell$containers$RootClass$READ_STATE[READ_STATE.STARTING.ordinal()] = 1;
            $SwitchMap$com$stericson$RootShell$containers$RootClass$READ_STATE[READ_STATE.FOUND_ANNOTATION.ordinal()] = 2;
        }
    }

    public static class AnnotationsFinder {
        private final String AVOIDDIRPATH;
        private List<File> classFiles = new ArrayList();

        public AnnotationsFinder() throws IOException {
            String[] strArr;
            String[] strArr2;
            StringBuilder sb = new StringBuilder();
            sb.append("stericson");
            sb.append(File.separator);
            sb.append("RootShell");
            sb.append(File.separator);
            this.AVOIDDIRPATH = sb.toString();
            System.out.println("Discovering root class annotations...");
            lookup(new File("src"), this.classFiles);
            System.out.println("Done discovering annotations. Building jar file.");
            File builtPath = getBuiltPath();
            if (builtPath != null) {
                StringBuilder sb2 = new StringBuilder();
                sb2.append("com");
                sb2.append(File.separator);
                sb2.append("stericson");
                sb2.append(File.separator);
                sb2.append("RootShell");
                sb2.append(File.separator);
                sb2.append("containers");
                sb2.append(File.separator);
                sb2.append("RootClass.class");
                String sb3 = sb2.toString();
                StringBuilder sb4 = new StringBuilder();
                sb4.append("com");
                sb4.append(File.separator);
                sb4.append("stericson");
                sb4.append(File.separator);
                sb4.append("RootShell");
                sb4.append(File.separator);
                sb4.append("containers");
                sb4.append(File.separator);
                sb4.append("RootClass$RootArgs.class");
                String sb5 = sb4.toString();
                StringBuilder sb6 = new StringBuilder();
                sb6.append("com");
                sb6.append(File.separator);
                sb6.append("stericson");
                sb6.append(File.separator);
                sb6.append("RootShell");
                sb6.append(File.separator);
                sb6.append("containers");
                sb6.append(File.separator);
                sb6.append("RootClass$AnnotationsFinder.class");
                String sb7 = sb6.toString();
                StringBuilder sb8 = new StringBuilder();
                sb8.append("com");
                sb8.append(File.separator);
                sb8.append("stericson");
                sb8.append(File.separator);
                sb8.append("RootShell");
                sb8.append(File.separator);
                sb8.append("containers");
                sb8.append(File.separator);
                sb8.append("RootClass$AnnotationsFinder$1.class");
                String sb9 = sb8.toString();
                StringBuilder sb10 = new StringBuilder();
                sb10.append("com");
                sb10.append(File.separator);
                sb10.append("stericson");
                sb10.append(File.separator);
                sb10.append("RootShell");
                sb10.append(File.separator);
                sb10.append("containers");
                sb10.append(File.separator);
                sb10.append("RootClass$AnnotationsFinder$2.class");
                String sb11 = sb10.toString();
                boolean z = -1 != System.getProperty("os.name").toLowerCase().indexOf("win");
                if (z) {
                    StringBuilder sb12 = new StringBuilder();
                    sb12.append(ServerProtocol.AUTHORIZATION_HEADER_DELIMITER);
                    sb12.append(sb3);
                    sb12.append(ServerProtocol.AUTHORIZATION_HEADER_DELIMITER);
                    sb12.append(sb5);
                    sb12.append(ServerProtocol.AUTHORIZATION_HEADER_DELIMITER);
                    sb12.append(sb7);
                    sb12.append(ServerProtocol.AUTHORIZATION_HEADER_DELIMITER);
                    sb12.append(sb9);
                    sb12.append(ServerProtocol.AUTHORIZATION_HEADER_DELIMITER);
                    sb12.append(sb11);
                    StringBuilder sb13 = new StringBuilder(sb12.toString());
                    for (File path : this.classFiles) {
                        StringBuilder sb14 = new StringBuilder();
                        sb14.append(ServerProtocol.AUTHORIZATION_HEADER_DELIMITER);
                        sb14.append(path.getPath());
                        sb13.append(sb14.toString());
                    }
                    StringBuilder sb15 = new StringBuilder();
                    sb15.append("jar cvf anbuild.jar");
                    sb15.append(sb13.toString());
                    strArr = new String[]{"cmd", "/C", sb15.toString()};
                } else {
                    ArrayList arrayList = new ArrayList();
                    arrayList.add("jar");
                    arrayList.add("cf");
                    arrayList.add("anbuild.jar");
                    arrayList.add(sb3);
                    arrayList.add(sb5);
                    arrayList.add(sb7);
                    arrayList.add(sb9);
                    arrayList.add(sb11);
                    for (File path2 : this.classFiles) {
                        arrayList.add(path2.getPath());
                    }
                    strArr = (String[]) arrayList.toArray(new String[arrayList.size()]);
                }
                ProcessBuilder processBuilder = new ProcessBuilder(strArr);
                processBuilder.directory(builtPath);
                try {
                    processBuilder.start().waitFor();
                } catch (IOException | InterruptedException unused) {
                }
                File file = new File("res/raw");
                if (!file.exists()) {
                    file.mkdirs();
                }
                System.out.println("Done building jar file. Creating dex file.");
                if (z) {
                    StringBuilder sb16 = new StringBuilder();
                    sb16.append("dx --dex --output=res/raw/anbuild.dex ");
                    sb16.append(builtPath);
                    sb16.append(File.separator);
                    sb16.append("anbuild.jar");
                    strArr2 = new String[]{"cmd", "/C", sb16.toString()};
                } else {
                    StringBuilder sb17 = new StringBuilder();
                    sb17.append(builtPath);
                    sb17.append(File.separator);
                    sb17.append("anbuild.jar");
                    strArr2 = new String[]{getPathToDx(), "--dex", "--output=res/raw/anbuild.dex", sb17.toString()};
                }
                try {
                    new ProcessBuilder(strArr2).start().waitFor();
                } catch (IOException | InterruptedException unused2) {
                }
            }
            System.out.println("All done. ::: anbuild.dex should now be in your project's res/raw/ folder :::");
        }

        /* access modifiers changed from: protected */
        public void lookup(File file, List<File> list) {
            File[] listFiles;
            String replace = file.toString().replace("src/", "");
            for (File file2 : file.listFiles()) {
                if (file2.isDirectory()) {
                    if (-1 == file2.getAbsolutePath().indexOf(this.AVOIDDIRPATH)) {
                        lookup(file2, list);
                    }
                } else if (file2.getName().endsWith(".java") && hasClassAnnotation(file2)) {
                    final String replace2 = file2.getName().replace(".java", "");
                    StringBuilder sb = new StringBuilder();
                    sb.append(getBuiltPath().toString());
                    sb.append(File.separator);
                    sb.append(replace);
                    for (File name : new File(sb.toString()).listFiles(new FilenameFilter() {
                        public boolean accept(File file, String str) {
                            return str.startsWith(replace2);
                        }
                    })) {
                        StringBuilder sb2 = new StringBuilder();
                        sb2.append(replace);
                        sb2.append(File.separator);
                        sb2.append(name.getName());
                        list.add(new File(sb2.toString()));
                    }
                }
            }
        }

        /* access modifiers changed from: protected */
        public boolean hasClassAnnotation(File file) {
            READ_STATE read_state = READ_STATE.STARTING;
            Pattern compile = Pattern.compile(" class ([A-Za-z0-9_]+)");
            try {
                BufferedReader bufferedReader = new BufferedReader(new FileReader(file));
                while (true) {
                    String readLine = bufferedReader.readLine();
                    if (readLine == null) {
                        break;
                    }
                    int i = AnonymousClass1.$SwitchMap$com$stericson$RootShell$containers$RootClass$READ_STATE[read_state.ordinal()];
                    if (i != 1) {
                        if (i == 2) {
                            Matcher matcher = compile.matcher(readLine);
                            if (matcher.find()) {
                                PrintStream printStream = System.out;
                                StringBuilder sb = new StringBuilder();
                                sb.append(" Found annotated class: ");
                                sb.append(matcher.group(0));
                                printStream.println(sb.toString());
                                return true;
                            }
                            PrintStream printStream2 = System.err;
                            StringBuilder sb2 = new StringBuilder();
                            sb2.append("Error: unmatched annotation in ");
                            sb2.append(file.getAbsolutePath());
                            printStream2.println(sb2.toString());
                            read_state = READ_STATE.STARTING;
                        }
                    } else if (-1 < readLine.indexOf("@RootClass.Candidate")) {
                        read_state = READ_STATE.FOUND_ANNOTATION;
                    }
                }
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (IOException e2) {
                e2.printStackTrace();
            }
            return false;
        }

        /* access modifiers changed from: protected */
        public String getPathToDx() throws IOException {
            File[] listFiles;
            String str;
            String str2 = System.getenv("ANDROID_HOME");
            if (str2 != null) {
                StringBuilder sb = new StringBuilder();
                sb.append(str2);
                sb.append(File.separator);
                sb.append("build-tools");
                String str3 = null;
                int i = 0;
                for (File file : new File(sb.toString()).listFiles()) {
                    if (file.getName().contains("-")) {
                        String[] split = file.getName().split("-");
                        if (split[1].contains("W")) {
                            str = String.valueOf(split[1].toCharArray()[0]);
                        } else {
                            str = split[1];
                        }
                    } else {
                        str = file.getName();
                    }
                    String[] split2 = str.split("[.]");
                    int parseInt = Integer.parseInt(split2[0]) * IConstValue.TIMEOUT;
                    if (split2.length > 1) {
                        parseInt += Integer.parseInt(split2[1]) * 100;
                        if (split2.length > 2) {
                            parseInt += Integer.parseInt(split2[2]);
                        }
                    }
                    if (parseInt > i) {
                        StringBuilder sb2 = new StringBuilder();
                        sb2.append(file.getAbsolutePath());
                        sb2.append(File.separator);
                        sb2.append("dx");
                        String sb3 = sb2.toString();
                        if (new File(sb3).exists()) {
                            str3 = sb3;
                            i = parseInt;
                        }
                    }
                }
                if (str3 != null) {
                    return str3;
                }
                throw new IOException("Error: unable to find dx binary in $ANDROID_HOME");
            }
            throw new IOException("Error: you need to set $ANDROID_HOME globally");
        }

        /* access modifiers changed from: protected */
        /* JADX WARNING: Removed duplicated region for block: B:7:0x0057  */
        public File getBuiltPath() {
            File file;
            StringBuilder sb = new StringBuilder();
            sb.append("out");
            sb.append(File.separator);
            sb.append("production");
            File file2 = new File(sb.toString());
            if (file2.isDirectory()) {
                File[] listFiles = file2.listFiles(new FileFilter() {
                    public boolean accept(File file) {
                        return file.isDirectory();
                    }
                });
                if (listFiles.length > 0) {
                    StringBuilder sb2 = new StringBuilder();
                    sb2.append(file2.getAbsolutePath());
                    sb2.append(File.separator);
                    sb2.append(listFiles[0].getName());
                    file = new File(sb2.toString());
                    if (file == null) {
                        StringBuilder sb3 = new StringBuilder();
                        sb3.append("bin");
                        sb3.append(File.separator);
                        sb3.append("classes");
                        File file3 = new File(sb3.toString());
                        if (file3.isDirectory()) {
                            return file3;
                        }
                    }
                    return file;
                }
            }
            file = null;
            if (file == null) {
            }
            return file;
        }
    }

    public @interface Candidate {
    }

    enum READ_STATE {
        STARTING,
        FOUND_ANNOTATION
    }

    public class RootArgs {
        public String[] args;

        public RootArgs() {
        }
    }

    public RootClass(String[] strArr) throws ClassNotFoundException, NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {
        String str = strArr[0];
        RootArgs rootArgs = new RootArgs();
        rootArgs.args = new String[(strArr.length - 1)];
        System.arraycopy(strArr, 1, rootArgs.args, 0, strArr.length - 1);
        Class.forName(str).getConstructor(new Class[]{RootArgs.class}).newInstance(new Object[]{rootArgs});
    }

    static void displayError(Exception exc) {
        PrintStream printStream = System.out;
        StringBuilder sb = new StringBuilder();
        sb.append("##ERR##");
        sb.append(exc.getMessage());
        sb.append("##");
        printStream.println(sb.toString());
        exc.printStackTrace();
    }

    public static void main(String[] strArr) {
        try {
            if (strArr.length == 0) {
                new AnnotationsFinder();
            } else {
                new RootClass(strArr);
            }
        } catch (Exception e) {
            displayError(e);
        }
    }
}