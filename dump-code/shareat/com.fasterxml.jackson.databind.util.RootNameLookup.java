package com.fasterxml.jackson.databind.util;

import com.fasterxml.jackson.core.io.SerializedString;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.cfg.MapperConfig;
import com.fasterxml.jackson.databind.type.ClassKey;
import java.io.Serializable;

public class RootNameLookup implements Serializable {
    private static final long serialVersionUID = 1;
    protected transient LRUMap<ClassKey, SerializedString> _rootNames;

    public SerializedString findRootName(JavaType javaType, MapperConfig<?> mapperConfig) {
        return findRootName(javaType.getRawClass(), mapperConfig);
    }

    /* JADX WARNING: Code restructure failed: missing block: B:10:0x002c, code lost:
        if (r0.hasSimpleName() != false) goto L_0x004f;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:11:0x002e, code lost:
        r0 = r5.getSimpleName();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:12:0x0032, code lost:
        r1 = new com.fasterxml.jackson.core.io.SerializedString(r0);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:13:0x0037, code lost:
        monitor-enter(r4);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:15:?, code lost:
        r4._rootNames.put(r2, r1);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:16:0x003d, code lost:
        monitor-exit(r4);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:26:0x004f, code lost:
        r0 = r0.getSimpleName();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:34:?, code lost:
        return r1;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:7:0x0016, code lost:
        r0 = r6.getAnnotationIntrospector().findRootName(r6.introspectClassAnnotations(r5).getClassInfo());
     */
    /* JADX WARNING: Code restructure failed: missing block: B:8:0x0026, code lost:
        if (r0 == null) goto L_0x002e;
     */
    public SerializedString findRootName(Class<?> cls, MapperConfig<?> mapperConfig) {
        ClassKey classKey = new ClassKey(cls);
        synchronized (this) {
            try {
                if (this._rootNames == null) {
                    this._rootNames = new LRUMap<>(20, 200);
                } else {
                    SerializedString serializedString = (SerializedString) this._rootNames.get(classKey);
                    if (serializedString != null) {
                        return serializedString;
                    }
                }
            }
        }
    }
}