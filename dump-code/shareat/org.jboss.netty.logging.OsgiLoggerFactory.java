package org.jboss.netty.logging;

import org.osgi.framework.BundleContext;
import org.osgi.service.log.LogService;
import org.osgi.util.tracker.ServiceTracker;

public class OsgiLoggerFactory extends InternalLoggerFactory {
    private final InternalLoggerFactory fallback;
    volatile LogService logService;
    private final ServiceTracker logServiceTracker;

    public OsgiLoggerFactory(BundleContext ctx) {
        this(ctx, null);
    }

    /*  JADX ERROR: IF instruction can be used only in fallback mode
        jadx.core.utils.exceptions.CodegenException: IF instruction can be used only in fallback mode
        	at jadx.core.codegen.InsnGen.fallbackOnlyInsn(InsnGen.java:571)
        	at jadx.core.codegen.InsnGen.makeInsnBody(InsnGen.java:477)
        	at jadx.core.codegen.InsnGen.makeInsn(InsnGen.java:242)
        	at jadx.core.codegen.InsnGen.makeInsn(InsnGen.java:213)
        	at jadx.core.codegen.RegionGen.makeSimpleBlock(RegionGen.java:109)
        	at jadx.core.codegen.RegionGen.makeRegion(RegionGen.java:55)
        	at jadx.core.codegen.RegionGen.makeSimpleRegion(RegionGen.java:92)
        	at jadx.core.codegen.RegionGen.makeRegion(RegionGen.java:58)
        	at jadx.core.codegen.RegionGen.makeRegionIndent(RegionGen.java:98)
        	at jadx.core.codegen.RegionGen.makeIf(RegionGen.java:142)
        	at jadx.core.codegen.RegionGen.makeRegion(RegionGen.java:62)
        	at jadx.core.codegen.RegionGen.makeSimpleRegion(RegionGen.java:92)
        	at jadx.core.codegen.RegionGen.makeRegion(RegionGen.java:58)
        	at jadx.core.codegen.RegionGen.makeSimpleRegion(RegionGen.java:92)
        	at jadx.core.codegen.RegionGen.makeRegion(RegionGen.java:58)
        	at jadx.core.codegen.RegionGen.makeSimpleRegion(RegionGen.java:92)
        	at jadx.core.codegen.RegionGen.makeRegion(RegionGen.java:58)
        	at jadx.core.codegen.MethodGen.addRegionInsns(MethodGen.java:210)
        	at jadx.core.codegen.MethodGen.addInstructions(MethodGen.java:203)
        	at jadx.core.codegen.ClassGen.addMethod(ClassGen.java:315)
        	at jadx.core.codegen.ClassGen.addMethods(ClassGen.java:261)
        	at jadx.core.codegen.ClassGen.addClassBody(ClassGen.java:224)
        	at jadx.core.codegen.ClassGen.addClassCode(ClassGen.java:109)
        	at jadx.core.codegen.ClassGen.makeClass(ClassGen.java:75)
        	at jadx.core.codegen.CodeGen.wrapCodeGen(CodeGen.java:44)
        	at jadx.core.codegen.CodeGen.generateJavaCode(CodeGen.java:32)
        	at jadx.core.codegen.CodeGen.generate(CodeGen.java:20)
        	at jadx.core.ProcessClass.process(ProcessClass.java:36)
        	at jadx.api.JadxDecompiler.processClass(JadxDecompiler.java:311)
        	at jadx.api.JavaClass.decompile(JavaClass.java:62)
        */
    /* JADX WARNING: Code restructure failed: missing block: B:7:0x0018, code lost:
        r5 = new org.jboss.netty.logging.JdkLoggerFactory();
     */
    public OsgiLoggerFactory(org.osgi.framework.BundleContext r4, org.jboss.netty.logging.InternalLoggerFactory r5) {
        /*
            r3 = this;
            r3.<init>()
            if (r4 != 0) goto L_0x000e
            java.lang.NullPointerException r0 = new java.lang.NullPointerException
            java.lang.String r1 = "ctx"
            r0.<init>(r1)
            throw r0
        L_0x000e:
            if (r5 != 0) goto L_0x001d
            org.jboss.netty.logging.InternalLoggerFactory r5 = org.jboss.netty.logging.InternalLoggerFactory.getDefaultFactory()
            boolean r0 = r5 instanceof org.jboss.netty.logging.OsgiLoggerFactory
            if (r0 == 0) goto L_0x001d
            org.jboss.netty.logging.JdkLoggerFactory r5 = new org.jboss.netty.logging.JdkLoggerFactory
            r5.<init>()
        L_0x001d:
            r3.fallback = r5
            org.jboss.netty.logging.OsgiLoggerFactory$1 r0 = new org.jboss.netty.logging.OsgiLoggerFactory$1
            java.lang.String r1 = "org.osgi.service.log.LogService"
            r2 = 0
            r0.<init>(r4, r1, r2)
            r3.logServiceTracker = r0
            org.osgi.util.tracker.ServiceTracker r0 = r3.logServiceTracker
            r0.open()
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: org.jboss.netty.logging.OsgiLoggerFactory.<init>(org.osgi.framework.BundleContext, org.jboss.netty.logging.InternalLoggerFactory):void");
    }

    public InternalLoggerFactory getFallback() {
        return this.fallback;
    }

    public LogService getLogService() {
        return this.logService;
    }

    public void destroy() {
        this.logService = null;
        this.logServiceTracker.close();
    }

    public InternalLogger newInstance(String name) {
        return new OsgiLogger(this, name, this.fallback.newInstance(name));
    }
}