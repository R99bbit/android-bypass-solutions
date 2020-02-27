package com.getkeepsafe.relinker;

import android.os.Build;
import android.os.Build.VERSION;
import com.getkeepsafe.relinker.ReLinker.LibraryLoader;

final class SystemLibraryLoader implements LibraryLoader {
    SystemLibraryLoader() {
    }

    public void loadLibrary(String libraryName) {
        System.loadLibrary(libraryName);
    }

    public void loadPath(String libraryPath) {
        System.load(libraryPath);
    }

    public String mapLibraryName(String libraryName) {
        return (!libraryName.startsWith("lib") || !libraryName.endsWith(".so")) ? System.mapLibraryName(libraryName) : libraryName;
    }

    public String unmapLibraryName(String mappedLibraryName) {
        return mappedLibraryName.substring(3, mappedLibraryName.length() - 3);
    }

    public String[] supportedAbis() {
        if (VERSION.SDK_INT >= 21 && Build.SUPPORTED_ABIS.length > 0) {
            return Build.SUPPORTED_ABIS;
        }
        if (!TextUtils.isEmpty(Build.CPU_ABI2)) {
            return new String[]{Build.CPU_ABI, Build.CPU_ABI2};
        }
        return new String[]{Build.CPU_ABI};
    }
}