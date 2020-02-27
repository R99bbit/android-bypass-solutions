package com.fasterxml.jackson.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.Locale;
import java.util.TimeZone;

@Target({ElementType.ANNOTATION_TYPE, ElementType.FIELD, ElementType.METHOD, ElementType.PARAMETER, ElementType.TYPE})
@JacksonAnnotation
@Retention(RetentionPolicy.RUNTIME)
public @interface JsonFormat {
    public static final String DEFAULT_LOCALE = "##default";
    public static final String DEFAULT_TIMEZONE = "##default";

    public enum Shape {
        ANY,
        SCALAR,
        ARRAY,
        OBJECT,
        NUMBER,
        NUMBER_FLOAT,
        NUMBER_INT,
        STRING,
        BOOLEAN;

        public boolean isNumeric() {
            return this == NUMBER || this == NUMBER_INT || this == NUMBER_FLOAT;
        }

        public boolean isStructured() {
            return this == OBJECT || this == ARRAY;
        }
    }

    public static class Value {
        private final Locale locale;
        private final String pattern;
        private final Shape shape;
        private final TimeZone timezone;

        public Value() {
            this((String) "", Shape.ANY, (String) "", (String) "");
        }

        public Value(JsonFormat jsonFormat) {
            this(jsonFormat.pattern(), jsonFormat.shape(), jsonFormat.locale(), jsonFormat.timezone());
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
            	at jadx.core.codegen.ClassGen.addInnerClasses(ClassGen.java:236)
            	at jadx.core.codegen.ClassGen.addClassBody(ClassGen.java:223)
            	at jadx.core.codegen.ClassGen.addClassCode(ClassGen.java:109)
            	at jadx.core.codegen.ClassGen.makeClass(ClassGen.java:75)
            	at jadx.core.codegen.CodeGen.wrapCodeGen(CodeGen.java:44)
            	at jadx.core.codegen.CodeGen.generateJavaCode(CodeGen.java:32)
            	at jadx.core.codegen.CodeGen.generate(CodeGen.java:20)
            	at jadx.core.ProcessClass.process(ProcessClass.java:36)
            	at jadx.api.JadxDecompiler.processClass(JadxDecompiler.java:311)
            	at jadx.api.JavaClass.decompile(JavaClass.java:62)
            */
        /* JADX WARNING: Code restructure failed: missing block: B:15:0x002e, code lost:
            r0 = java.util.TimeZone.getTimeZone(r7);
         */
        /* JADX WARNING: Illegal instructions before constructor call commented (this can break semantics) */
        public Value(java.lang.String r4, com.fasterxml.jackson.annotation.JsonFormat.Shape r5, java.lang.String r6, java.lang.String r7) {
            /*
                r3 = this;
                r0 = 0
                if (r6 == 0) goto L_0x0012
                int r1 = r6.length()
                if (r1 == 0) goto L_0x0012
                java.lang.String r1 = "##default"
                boolean r1 = r1.equals(r6)
                if (r1 == 0) goto L_0x0028
            L_0x0012:
                r1 = r0
            L_0x0013:
                if (r7 == 0) goto L_0x0024
                int r2 = r7.length()
                if (r2 == 0) goto L_0x0024
                java.lang.String r2 = "##default"
                boolean r2 = r2.equals(r7)
                if (r2 == 0) goto L_0x002e
            L_0x0024:
                r3.<init>(r4, r5, r1, r0)
                return
            L_0x0028:
                java.util.Locale r1 = new java.util.Locale
                r1.<init>(r6)
                goto L_0x0013
            L_0x002e:
                java.util.TimeZone r0 = java.util.TimeZone.getTimeZone(r7)
                goto L_0x0024
            */
            throw new UnsupportedOperationException("Method not decompiled: com.fasterxml.jackson.annotation.JsonFormat.Value.<init>(java.lang.String, com.fasterxml.jackson.annotation.JsonFormat$Shape, java.lang.String, java.lang.String):void");
        }

        public Value(String str, Shape shape2, Locale locale2, TimeZone timeZone) {
            this.pattern = str;
            this.shape = shape2;
            this.locale = locale2;
            this.timezone = timeZone;
        }

        public Value withPattern(String str) {
            return new Value(str, this.shape, this.locale, this.timezone);
        }

        public Value withShape(Shape shape2) {
            return new Value(this.pattern, shape2, this.locale, this.timezone);
        }

        public Value withLocale(Locale locale2) {
            return new Value(this.pattern, this.shape, locale2, this.timezone);
        }

        public Value withTimeZone(TimeZone timeZone) {
            return new Value(this.pattern, this.shape, this.locale, timeZone);
        }

        public String getPattern() {
            return this.pattern;
        }

        public Shape getShape() {
            return this.shape;
        }

        public Locale getLocale() {
            return this.locale;
        }

        public TimeZone getTimeZone() {
            return this.timezone;
        }
    }

    String locale() default "##default";

    String pattern() default "";

    Shape shape() default Shape.ANY;

    String timezone() default "##default";
}