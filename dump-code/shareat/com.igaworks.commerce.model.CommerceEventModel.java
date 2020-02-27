package com.igaworks.commerce.model;

import android.util.Pair;
import com.google.firebase.analytics.FirebaseAnalytics.Param;
import java.util.List;
import org.json.JSONObject;

public class CommerceEventModel {
    private String eventName;
    private long mtime;
    private List<Pair<String, Object>> params;

    public CommerceEventModel(String eventName2, List<Pair<String, Object>> params2, long mtime2) {
        this.eventName = eventName2;
        this.params = params2;
        this.mtime = mtime2;
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
    /* JADX WARNING: Code restructure failed: missing block: B:2:0x0006, code lost:
        r0 = com.igaworks.impl.CommonFrameworkImpl.getContext();
     */
    public CommerceEventModel(java.lang.String r11) {
        /*
            r10 = this;
            r10.<init>()
            r0 = 0
            if (r0 != 0) goto L_0x000a
            android.content.Context r0 = com.igaworks.impl.CommonFrameworkImpl.getContext()
        L_0x000a:
            org.json.JSONObject r2 = new org.json.JSONObject     // Catch:{ Exception -> 0x006a }
            r2.<init>(r11)     // Catch:{ Exception -> 0x006a }
            java.lang.String r7 = "event_type"     // Catch:{ Exception -> 0x006a }
            boolean r7 = r2.has(r7)     // Catch:{ Exception -> 0x006a }
            if (r7 == 0) goto L_0x0021     // Catch:{ Exception -> 0x006a }
            java.lang.String r7 = "event_type"     // Catch:{ Exception -> 0x006a }
            java.lang.String r7 = r2.getString(r7)     // Catch:{ Exception -> 0x006a }
            r10.eventName = r7     // Catch:{ Exception -> 0x006a }
        L_0x0021:
            java.lang.String r7 = "value"     // Catch:{ Exception -> 0x006a }
            boolean r7 = r2.has(r7)     // Catch:{ Exception -> 0x006a }
            if (r7 == 0) goto L_0x0044     // Catch:{ Exception -> 0x006a }
            java.util.ArrayList r6 = new java.util.ArrayList     // Catch:{ Exception -> 0x006a }
            r6.<init>()     // Catch:{ Exception -> 0x006a }
            java.lang.String r7 = "value"     // Catch:{ Exception -> 0x006a }
            org.json.JSONObject r5 = r2.getJSONObject(r7)     // Catch:{ Exception -> 0x006a }
            if (r5 == 0) goto L_0x0044     // Catch:{ Exception -> 0x006a }
            java.util.Iterator r4 = r5.keys()     // Catch:{ Exception -> 0x006a }
        L_0x003c:
            boolean r7 = r4.hasNext()     // Catch:{ Exception -> 0x006a }
            if (r7 != 0) goto L_0x0057     // Catch:{ Exception -> 0x006a }
            r10.params = r6     // Catch:{ Exception -> 0x006a }
        L_0x0044:
            java.lang.String r7 = "mtime"     // Catch:{ Exception -> 0x006a }
            boolean r7 = r2.has(r7)     // Catch:{ Exception -> 0x006a }
            if (r7 == 0) goto L_0x0056     // Catch:{ Exception -> 0x006a }
            java.lang.String r7 = "mtime"     // Catch:{ Exception -> 0x006a }
            long r8 = r2.getLong(r7)     // Catch:{ Exception -> 0x006a }
            r10.mtime = r8     // Catch:{ Exception -> 0x006a }
        L_0x0056:
            return     // Catch:{ Exception -> 0x006a }
        L_0x0057:
            java.lang.Object r3 = r4.next()     // Catch:{ Exception -> 0x006a }
            java.lang.String r3 = (java.lang.String) r3     // Catch:{ Exception -> 0x006a }
            android.util.Pair r7 = new android.util.Pair     // Catch:{ Exception -> 0x006a }
            java.lang.Object r8 = r5.get(r3)     // Catch:{ Exception -> 0x006a }
            r7.<init>(r3, r8)     // Catch:{ Exception -> 0x006a }
            r6.add(r7)     // Catch:{ Exception -> 0x006a }
            goto L_0x003c
        L_0x006a:
            r1 = move-exception
            r1.printStackTrace()
            goto L_0x0056
        */
        throw new UnsupportedOperationException("Method not decompiled: com.igaworks.commerce.model.CommerceEventModel.<init>(java.lang.String):void");
    }

    public CommerceEventModel() {
    }

    public String getEventName() {
        return this.eventName;
    }

    public void setEventName(String eventName2) {
        this.eventName = eventName2;
    }

    public List<Pair<String, Object>> getParams() {
        return this.params;
    }

    public void setParams(List<Pair<String, Object>> params2) {
        this.params = params2;
    }

    public long getMtime() {
        return this.mtime;
    }

    public void setMtime(long mtime2) {
        this.mtime = mtime2;
    }

    public String toString() {
        return toJson().toString();
    }

    public JSONObject toJson() {
        JSONObject root = new JSONObject();
        try {
            root.put("name", this.eventName);
            JSONObject params2 = new JSONObject();
            if (this.params != null) {
                for (Pair<String, Object> nvp : this.params) {
                    params2.put((String) nvp.first, nvp.second);
                }
            }
            root.put(Param.VALUE, params2);
            root.put("mtime", this.mtime);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return root;
    }
}