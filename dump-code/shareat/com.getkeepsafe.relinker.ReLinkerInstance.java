package com.getkeepsafe.relinker;

import android.content.Context;
import android.util.Log;
import com.getkeepsafe.relinker.ReLinker.LibraryInstaller;
import com.getkeepsafe.relinker.ReLinker.LibraryLoader;
import com.getkeepsafe.relinker.ReLinker.LoadListener;
import com.getkeepsafe.relinker.ReLinker.Logger;
import com.getkeepsafe.relinker.elf.ElfParser;
import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public class ReLinkerInstance {
    private static final String LIB_DIR = "lib";
    protected boolean force;
    protected final LibraryInstaller libraryInstaller;
    protected final LibraryLoader libraryLoader;
    protected final Set<String> loadedLibraries;
    protected Logger logger;
    protected boolean recursive;

    protected ReLinkerInstance() {
        this(new SystemLibraryLoader(), new ApkLibraryInstaller());
    }

    protected ReLinkerInstance(LibraryLoader libraryLoader2, LibraryInstaller libraryInstaller2) {
        this.loadedLibraries = new HashSet();
        if (libraryLoader2 == null) {
            throw new IllegalArgumentException("Cannot pass null library loader");
        } else if (libraryInstaller2 == null) {
            throw new IllegalArgumentException("Cannot pass null library installer");
        } else {
            this.libraryLoader = libraryLoader2;
            this.libraryInstaller = libraryInstaller2;
        }
    }

    public ReLinkerInstance log(Logger logger2) {
        this.logger = logger2;
        return this;
    }

    public ReLinkerInstance force() {
        this.force = true;
        return this;
    }

    public ReLinkerInstance recursively() {
        this.recursive = true;
        return this;
    }

    public void loadLibrary(Context context, String library) {
        loadLibrary(context, library, null, null);
    }

    public void loadLibrary(Context context, String library, String version) {
        loadLibrary(context, library, version, null);
    }

    public void loadLibrary(Context context, String library, LoadListener listener) {
        loadLibrary(context, library, null, listener);
    }

    public void loadLibrary(Context context, String library, String version, LoadListener listener) {
        if (context == null) {
            throw new IllegalArgumentException("Given context is null");
        } else if (TextUtils.isEmpty(library)) {
            throw new IllegalArgumentException("Given library is either null or empty");
        } else {
            log("Beginning load of %s...", library);
            if (listener == null) {
                loadLibraryInternal(context, library, version);
                return;
            }
            final Context context2 = context;
            final String str = library;
            final String str2 = version;
            final LoadListener loadListener = listener;
            new Thread(new Runnable() {
                public void run() {
                    try {
                        ReLinkerInstance.this.loadLibraryInternal(context2, str, str2);
                        loadListener.success();
                    } catch (UnsatisfiedLinkError e) {
                        loadListener.failure(e);
                    } catch (MissingLibraryException e2) {
                        loadListener.failure(e2);
                    }
                }
            }).start();
        }
    }

    /* access modifiers changed from: private */
    public void loadLibraryInternal(Context context, String library, String version) {
        ElfParser parser;
        ElfParser parser2;
        if (!this.loadedLibraries.contains(library) || this.force) {
            try {
                this.libraryLoader.loadLibrary(library);
                this.loadedLibraries.add(library);
                log("%s (%s) was loaded normally!", library, version);
                return;
            } catch (UnsatisfiedLinkError e) {
                log("Loading the library normally failed: %s", Log.getStackTraceString(e));
                log("%s (%s) was not loaded normally, re-linking...", library, version);
                File workaroundFile = getWorkaroundLibFile(context, library, version);
                if (!workaroundFile.exists() || this.force) {
                    if (this.force) {
                        log("Forcing a re-link of %s (%s)...", library, version);
                    }
                    cleanupOldLibFiles(context, library, version);
                    this.libraryInstaller.installLibrary(context, this.libraryLoader.supportedAbis(), this.libraryLoader.mapLibraryName(library), workaroundFile, this);
                }
                try {
                    if (this.recursive) {
                        parser = null;
                        parser2 = new ElfParser(workaroundFile);
                        List<String> dependencies = parser2.parseNeededDependencies();
                        parser2.close();
                        for (String dependency : dependencies) {
                            loadLibrary(context, this.libraryLoader.unmapLibraryName(dependency));
                        }
                    }
                } catch (IOException e2) {
                }
                this.libraryLoader.loadPath(workaroundFile.getAbsolutePath());
                this.loadedLibraries.add(library);
                log("%s (%s) was re-linked!", library, version);
                return;
            } catch (Throwable th) {
                th = th;
                parser = parser2;
            }
        } else {
            log("%s already loaded previously!", library);
            return;
        }
        parser.close();
        throw th;
    }

    /* access modifiers changed from: protected */
    public File getWorkaroundLibDir(Context context) {
        return context.getDir(LIB_DIR, 0);
    }

    /* access modifiers changed from: protected */
    public File getWorkaroundLibFile(Context context, String library, String version) {
        String libName = this.libraryLoader.mapLibraryName(library);
        if (TextUtils.isEmpty(version)) {
            return new File(getWorkaroundLibDir(context), libName);
        }
        return new File(getWorkaroundLibDir(context), libName + "." + version);
    }

    /* access modifiers changed from: protected */
    public void cleanupOldLibFiles(Context context, String library, String currentVersion) {
        File workaroundDir = getWorkaroundLibDir(context);
        File workaroundFile = getWorkaroundLibFile(context, library, currentVersion);
        final String mappedLibraryName = this.libraryLoader.mapLibraryName(library);
        File[] existingFiles = workaroundDir.listFiles(new FilenameFilter() {
            public boolean accept(File dir, String filename) {
                return filename.startsWith(mappedLibraryName);
            }
        });
        if (existingFiles != null) {
            for (File file : existingFiles) {
                if (this.force || !file.getAbsolutePath().equals(workaroundFile.getAbsolutePath())) {
                    file.delete();
                }
            }
        }
    }

    public void log(String format, Object... args) {
        log(String.format(Locale.US, format, args));
    }

    public void log(String message) {
        if (this.logger != null) {
            this.logger.log(message);
        }
    }
}