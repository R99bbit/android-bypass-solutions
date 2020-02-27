package com.github.nkzawa.socketio.parser;

import com.github.nkzawa.emitter.Emitter;
import com.github.nkzawa.socketio.parser.Binary.DeconstructedPacket;
import com.igaworks.core.RequestParameter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

public class Parser {
    public static final int ACK = 3;
    public static final int BINARY_ACK = 6;
    public static final int BINARY_EVENT = 5;
    public static final int CONNECT = 0;
    public static final int DISCONNECT = 1;
    public static final int ERROR = 4;
    public static final int EVENT = 2;
    /* access modifiers changed from: private */
    public static final Logger logger = Logger.getLogger(Parser.class.getName());
    public static int protocol = 4;
    public static String[] types = {"CONNECT", "DISCONNECT", "EVENT", "ACK", RequestParameter.ERROR, "BINARY_EVENT", "BINARY_ACK"};

    static class BinaryReconstructor {
        List<byte[]> buffers = new ArrayList();
        public Packet reconPack;

        BinaryReconstructor(Packet packet) {
            this.reconPack = packet;
        }

        public Packet takeBinaryData(byte[] binData) {
            this.buffers.add(binData);
            if (this.buffers.size() != this.reconPack.attachments) {
                return null;
            }
            Packet packet = Binary.reconstructPacket(this.reconPack, (byte[][]) this.buffers.toArray(new byte[this.buffers.size()][]));
            finishReconstruction();
            return packet;
        }

        public void finishReconstruction() {
            this.reconPack = null;
            this.buffers = new ArrayList();
        }
    }

    public static class Decoder extends Emitter {
        public static String EVENT_DECODED = "decoded";
        BinaryReconstructor reconstructor = null;

        public void add(String obj) {
            Packet packet = decodeString(obj);
            if (5 == packet.type || 6 == packet.type) {
                this.reconstructor = new BinaryReconstructor(packet);
                if (this.reconstructor.reconPack.attachments == 0) {
                    emit(EVENT_DECODED, packet);
                    return;
                }
                return;
            }
            emit(EVENT_DECODED, packet);
        }

        public void add(byte[] obj) {
            if (this.reconstructor == null) {
                throw new RuntimeException("got binary data when not reconstructing a packet");
            }
            Packet packet = this.reconstructor.takeBinaryData(obj);
            if (packet != null) {
                this.reconstructor = null;
                emit(EVENT_DECODED, packet);
            }
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
            	at jadx.core.codegen.RegionGen.makeLoop(RegionGen.java:205)
            	at jadx.core.codegen.RegionGen.makeRegion(RegionGen.java:66)
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
        private static com.github.nkzawa.socketio.parser.Packet decodeString(java.lang.String r14) {
            /*
                r13 = 1
                r12 = 0
                com.github.nkzawa.socketio.parser.Packet r8 = new com.github.nkzawa.socketio.parser.Packet
                r8.<init>()
                r3 = 0
                int r5 = r14.length()
                char r9 = r14.charAt(r12)
                int r9 = java.lang.Character.getNumericValue(r9)
                r8.type = r9
                int r9 = r8.type
                if (r9 < 0) goto L_0x0023
                int r9 = r8.type
                java.lang.String[] r10 = com.github.nkzawa.socketio.parser.Parser.types
                int r10 = r10.length
                int r10 = r10 + -1
                if (r9 <= r10) goto L_0x0028
            L_0x0023:
                com.github.nkzawa.socketio.parser.Packet r8 = com.github.nkzawa.socketio.parser.Parser.error()
            L_0x0027:
                return r8
            L_0x0028:
                r9 = 5
                int r10 = r8.type
                if (r9 == r10) goto L_0x0032
                r9 = 6
                int r10 = r8.type
                if (r9 != r10) goto L_0x0063
            L_0x0032:
                java.lang.String r9 = "-"
                boolean r9 = r14.contains(r9)
                if (r9 == 0) goto L_0x003d
                if (r5 > r13) goto L_0x0042
            L_0x003d:
                com.github.nkzawa.socketio.parser.Packet r8 = com.github.nkzawa.socketio.parser.Parser.error()
                goto L_0x0027
            L_0x0042:
                java.lang.StringBuilder r0 = new java.lang.StringBuilder
                r0.<init>()
            L_0x0047:
                int r3 = r3 + 1
                char r9 = r14.charAt(r3)
                r10 = 45
                if (r9 == r10) goto L_0x0059
                char r9 = r14.charAt(r3)
                r0.append(r9)
                goto L_0x0047
            L_0x0059:
                java.lang.String r9 = r0.toString()
                int r9 = java.lang.Integer.parseInt(r9)
                r8.attachments = r9
            L_0x0063:
                int r9 = r3 + 1
                if (r5 <= r9) goto L_0x00f3
                r9 = 47
                int r10 = r3 + 1
                char r10 = r14.charAt(r10)
                if (r9 != r10) goto L_0x00f3
                java.lang.StringBuilder r7 = new java.lang.StringBuilder
                r7.<init>()
            L_0x0076:
                int r3 = r3 + 1
                char r1 = r14.charAt(r3)
                r9 = 44
                if (r9 != r1) goto L_0x00eb
            L_0x0080:
                java.lang.String r9 = r7.toString()
                r8.nsp = r9
            L_0x0086:
                int r9 = r3 + 1
                if (r5 <= r9) goto L_0x00bc
                int r9 = r3 + 1
                char r9 = r14.charAt(r9)
                java.lang.Character r6 = java.lang.Character.valueOf(r9)
                char r9 = r6.charValue()
                int r9 = java.lang.Character.getNumericValue(r9)
                r10 = -1
                if (r9 <= r10) goto L_0x00bc
                java.lang.StringBuilder r4 = new java.lang.StringBuilder
                r4.<init>()
            L_0x00a4:
                int r3 = r3 + 1
                char r1 = r14.charAt(r3)
                int r9 = java.lang.Character.getNumericValue(r1)
                if (r9 >= 0) goto L_0x00f9
                int r3 = r3 + -1
            L_0x00b2:
                java.lang.String r9 = r4.toString()     // Catch:{ NumberFormatException -> 0x0101 }
                int r9 = java.lang.Integer.parseInt(r9)     // Catch:{ NumberFormatException -> 0x0101 }
                r8.id = r9     // Catch:{ NumberFormatException -> 0x0101 }
            L_0x00bc:
                int r9 = r3 + 1
                if (r5 <= r9) goto L_0x00d4
                int r3 = r3 + 1
                r14.charAt(r3)     // Catch:{ JSONException -> 0x0108 }
                org.json.JSONTokener r9 = new org.json.JSONTokener     // Catch:{ JSONException -> 0x0108 }
                java.lang.String r10 = r14.substring(r3)     // Catch:{ JSONException -> 0x0108 }
                r9.<init>(r10)     // Catch:{ JSONException -> 0x0108 }
                java.lang.Object r9 = r9.nextValue()     // Catch:{ JSONException -> 0x0108 }
                r8.data = r9     // Catch:{ JSONException -> 0x0108 }
            L_0x00d4:
                java.util.logging.Logger r9 = com.github.nkzawa.socketio.parser.Parser.logger
                java.lang.String r10 = "decoded %s as %s"
                r11 = 2
                java.lang.Object[] r11 = new java.lang.Object[r11]
                r11[r12] = r14
                r11[r13] = r8
                java.lang.String r10 = java.lang.String.format(r10, r11)
                r9.fine(r10)
                goto L_0x0027
            L_0x00eb:
                r7.append(r1)
                int r9 = r3 + 1
                if (r9 != r5) goto L_0x0076
                goto L_0x0080
            L_0x00f3:
                java.lang.String r9 = "/"
                r8.nsp = r9
                goto L_0x0086
            L_0x00f9:
                r4.append(r1)
                int r9 = r3 + 1
                if (r9 != r5) goto L_0x00a4
                goto L_0x00b2
            L_0x0101:
                r2 = move-exception
                com.github.nkzawa.socketio.parser.Packet r8 = com.github.nkzawa.socketio.parser.Parser.error()
                goto L_0x0027
            L_0x0108:
                r2 = move-exception
                com.github.nkzawa.socketio.parser.Packet r8 = com.github.nkzawa.socketio.parser.Parser.error()
                goto L_0x0027
            */
            throw new UnsupportedOperationException("Method not decompiled: com.github.nkzawa.socketio.parser.Parser.Decoder.decodeString(java.lang.String):com.github.nkzawa.socketio.parser.Packet");
        }

        public void destroy() {
            if (this.reconstructor != null) {
                this.reconstructor.finishReconstruction();
            }
        }
    }

    public static class Encoder {

        public interface Callback {
            void call(Object[] objArr);
        }

        public void encode(Packet obj, Callback callback) {
            Parser.logger.fine(String.format("encoding packet %s", new Object[]{obj}));
            if (5 == obj.type || 6 == obj.type) {
                encodeAsBinary(obj, callback);
                return;
            }
            callback.call(new String[]{encodeAsString(obj)});
        }

        private String encodeAsString(Packet obj) {
            StringBuilder str = new StringBuilder();
            boolean nsp = false;
            str.append(obj.type);
            if (5 == obj.type || 6 == obj.type) {
                str.append(obj.attachments);
                str.append("-");
            }
            if (!(obj.nsp == null || obj.nsp.length() == 0 || "/".equals(obj.nsp))) {
                nsp = true;
                str.append(obj.nsp);
            }
            if (obj.id >= 0) {
                if (nsp) {
                    str.append(",");
                    nsp = false;
                }
                str.append(obj.id);
            }
            if (obj.data != null) {
                if (nsp) {
                    str.append(",");
                }
                str.append(obj.data);
            }
            Parser.logger.fine(String.format("encoded %s as %s", new Object[]{obj, str}));
            return str.toString();
        }

        private void encodeAsBinary(Packet obj, Callback callback) {
            DeconstructedPacket deconstruction = Binary.deconstructPacket(obj);
            String pack = encodeAsString(deconstruction.packet);
            List<Object> buffers = new ArrayList<>(Arrays.asList(deconstruction.buffers));
            buffers.add(0, pack);
            callback.call(buffers.toArray());
        }
    }

    private Parser() {
    }

    /* access modifiers changed from: private */
    public static Packet<String> error() {
        return new Packet<>(4, "parser error");
    }
}