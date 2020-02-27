package com.fasterxml.jackson.core.util;

import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.core.Versioned;
import java.io.BufferedReader;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UnsupportedEncodingException;
import java.util.Properties;
import java.util.regex.Pattern;

public class VersionUtil {
    private static final Pattern VERSION_SEPARATOR = Pattern.compile("[-_./;:]");
    private final Version _version;

    protected VersionUtil() {
        Version version = null;
        try {
            version = versionFor(getClass());
        } catch (Exception e) {
            System.err.println("ERROR: Failed to load Version information from " + getClass());
        }
        this._version = version == null ? Version.unknownVersion() : version;
    }

    public Version version() {
        return this._version;
    }

    public static Version versionFor(Class<?> cls) {
        Version packageVersionFor = packageVersionFor(cls);
        if (packageVersionFor != null) {
            return packageVersionFor;
        }
        InputStream resourceAsStream = cls.getResourceAsStream("VERSION.txt");
        if (resourceAsStream == null) {
            return Version.unknownVersion();
        }
        try {
            return doReadVersion(new InputStreamReader(resourceAsStream, "UTF-8"));
        } catch (UnsupportedEncodingException e) {
            return Version.unknownVersion();
        } finally {
            _close(resourceAsStream);
        }
    }

    public static Version packageVersionFor(Class<?> cls) {
        Class<?> cls2;
        try {
            cls2 = Class.forName(cls.getPackage().getName() + ".PackageVersion", true, cls.getClassLoader());
            return ((Versioned) cls2.newInstance()).version();
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to get Versioned out of " + cls2);
        } catch (Exception e2) {
            return null;
        }
    }

    /* JADX WARNING: Code restructure failed: missing block: B:17:0x002b, code lost:
        r1 = r0;
        r2 = r0;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:19:0x0031, code lost:
        r0 = move-exception;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:20:0x0032, code lost:
        _close(r3);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:21:0x0035, code lost:
        throw r0;
     */
    /* JADX WARNING: Failed to process nested try/catch */
    /* JADX WARNING: Removed duplicated region for block: B:11:0x001b  */
    /* JADX WARNING: Removed duplicated region for block: B:13:0x0021  */
    /* JADX WARNING: Removed duplicated region for block: B:19:0x0031 A[ExcHandler: all (r0v1 'th' java.lang.Throwable A[CUSTOM_DECLARE]), Splitter:B:1:0x0006] */
    private static Version doReadVersion(Reader reader) {
        String str;
        String str2;
        String str3 = null;
        BufferedReader bufferedReader = new BufferedReader(reader);
        try {
            str = bufferedReader.readLine();
            if (str != null) {
                str2 = bufferedReader.readLine();
                if (str2 != null) {
                    str3 = bufferedReader.readLine();
                }
            } else {
                str2 = str3;
            }
            _close(bufferedReader);
        } catch (IOException e) {
            str2 = str3;
        } catch (Throwable th) {
        }
        if (str2 != null) {
            str2 = str2.trim();
        }
        if (str3 != null) {
            str3 = str3.trim();
        }
        return parseVersion(str, str2, str3);
        _close(bufferedReader);
        if (str2 != null) {
        }
        if (str3 != null) {
        }
        return parseVersion(str, str2, str3);
    }

    public static Version mavenVersionFor(ClassLoader classLoader, String str, String str2) {
        InputStream resourceAsStream = classLoader.getResourceAsStream("META-INF/maven/" + str.replaceAll("\\.", "/") + "/" + str2 + "/pom.properties");
        if (resourceAsStream != null) {
            try {
                Properties properties = new Properties();
                properties.load(resourceAsStream);
                return parseVersion(properties.getProperty("version"), properties.getProperty("groupId"), properties.getProperty("artifactId"));
            } catch (IOException e) {
            } finally {
                _close(resourceAsStream);
            }
        }
        return Version.unknownVersion();
    }

    public static Version parseVersion(String str, String str2, String str3) {
        String str4 = null;
        int i = 0;
        if (str != null) {
            String trim = str.trim();
            if (trim.length() > 0) {
                String[] split = VERSION_SEPARATOR.split(trim);
                int parseVersionPart = parseVersionPart(split[0]);
                int i2 = split.length > 1 ? parseVersionPart(split[1]) : 0;
                if (split.length > 2) {
                    i = parseVersionPart(split[2]);
                }
                if (split.length > 3) {
                    str4 = split[3];
                }
                return new Version(parseVersionPart, i2, i, str4, str2, str3);
            }
        }
        return null;
    }

    protected static int parseVersionPart(String str) {
        int length = str.length();
        int i = 0;
        for (int i2 = 0; i2 < length; i2++) {
            char charAt = str.charAt(i2);
            if (charAt > '9' || charAt < '0') {
                break;
            }
            i = (i * 10) + (charAt - '0');
        }
        return i;
    }

    private static final void _close(Closeable closeable) {
        try {
            closeable.close();
        } catch (IOException e) {
        }
    }

    public static final void throwInternal() {
        throw new RuntimeException("Internal error: this code path should never get executed");
    }
}