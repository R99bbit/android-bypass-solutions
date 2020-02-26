package org.acra.collector;

import android.util.SparseArray;
import com.google.android.gms.common.Scopes;
import com.google.firebase.analytics.FirebaseAnalytics.Param;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;

public class MediaCodecListCollector {
    private static final String[] AAC_TYPES = {"aac", "AAC"};
    private static final String[] AVC_TYPES = {"avc", "h264", "AVC", "H264"};
    private static final String COLOR_FORMAT_PREFIX = "COLOR_";
    private static final String[] H263_TYPES = {"h263", "H263"};
    private static final String[] MPEG4_TYPES = {"mp4", "mpeg4", "MP4", "MPEG4"};
    private static Class<?> codecCapabilitiesClass;
    private static Field colorFormatsField;
    private static Method getCapabilitiesForTypeMethod;
    private static Method getCodecInfoAtMethod;
    private static Method getNameMethod;
    private static Method getSupportedTypesMethod;
    private static Method isEncoderMethod;
    private static Field levelField;
    private static SparseArray<String> mAACProfileValues = new SparseArray<>();
    private static SparseArray<String> mAVCLevelValues = new SparseArray<>();
    private static SparseArray<String> mAVCProfileValues = new SparseArray<>();
    private static SparseArray<String> mColorFormatValues = new SparseArray<>();
    private static SparseArray<String> mH263LevelValues = new SparseArray<>();
    private static SparseArray<String> mH263ProfileValues = new SparseArray<>();
    private static SparseArray<String> mMPEG4LevelValues = new SparseArray<>();
    private static SparseArray<String> mMPEG4ProfileValues = new SparseArray<>();
    private static Class<?> mediaCodecInfoClass;
    private static Class<?> mediaCodecListClass;
    private static Field profileField;
    private static Field profileLevelsField;

    /* renamed from: org.acra.collector.MediaCodecListCollector$1 reason: invalid class name */
    static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$org$acra$collector$MediaCodecListCollector$CodecType = new int[CodecType.values().length];

        /* JADX WARNING: Can't wrap try/catch for region: R(10:0|1|2|3|4|5|6|7|8|10) */
        /* JADX WARNING: Can't wrap try/catch for region: R(8:0|1|2|3|4|5|6|(3:7|8|10)) */
        /* JADX WARNING: Failed to process nested try/catch */
        /* JADX WARNING: Missing exception handler attribute for start block: B:3:0x0014 */
        /* JADX WARNING: Missing exception handler attribute for start block: B:5:0x001f */
        /* JADX WARNING: Missing exception handler attribute for start block: B:7:0x002a */
        static {
            $SwitchMap$org$acra$collector$MediaCodecListCollector$CodecType[CodecType.AVC.ordinal()] = 1;
            $SwitchMap$org$acra$collector$MediaCodecListCollector$CodecType[CodecType.H263.ordinal()] = 2;
            $SwitchMap$org$acra$collector$MediaCodecListCollector$CodecType[CodecType.MPEG4.ordinal()] = 3;
            try {
                $SwitchMap$org$acra$collector$MediaCodecListCollector$CodecType[CodecType.AAC.ordinal()] = 4;
            } catch (NoSuchFieldError unused) {
            }
        }
    }

    private enum CodecType {
        AVC,
        H263,
        MPEG4,
        AAC
    }

    static {
        Field[] fields;
        Field[] fields2;
        mediaCodecListClass = null;
        getCodecInfoAtMethod = null;
        mediaCodecInfoClass = null;
        getNameMethod = null;
        isEncoderMethod = null;
        getSupportedTypesMethod = null;
        getCapabilitiesForTypeMethod = null;
        codecCapabilitiesClass = null;
        colorFormatsField = null;
        profileLevelsField = null;
        profileField = null;
        levelField = null;
        try {
            mediaCodecListClass = Class.forName("android.media.MediaCodecList");
            getCodecInfoAtMethod = mediaCodecListClass.getMethod("getCodecInfoAt", new Class[]{Integer.TYPE});
            mediaCodecInfoClass = Class.forName("android.media.MediaCodecInfo");
            getNameMethod = mediaCodecInfoClass.getMethod("getName", new Class[0]);
            isEncoderMethod = mediaCodecInfoClass.getMethod("isEncoder", new Class[0]);
            getSupportedTypesMethod = mediaCodecInfoClass.getMethod("getSupportedTypes", new Class[0]);
            getCapabilitiesForTypeMethod = mediaCodecInfoClass.getMethod("getCapabilitiesForType", new Class[]{String.class});
            codecCapabilitiesClass = Class.forName("android.media.MediaCodecInfo$CodecCapabilities");
            colorFormatsField = codecCapabilitiesClass.getField("colorFormats");
            profileLevelsField = codecCapabilitiesClass.getField("profileLevels");
            for (Field field : codecCapabilitiesClass.getFields()) {
                if (Modifier.isStatic(field.getModifiers()) && Modifier.isFinal(field.getModifiers()) && field.getName().startsWith(COLOR_FORMAT_PREFIX)) {
                    mColorFormatValues.put(field.getInt(null), field.getName());
                }
            }
            Class<?> cls = Class.forName("android.media.MediaCodecInfo$CodecProfileLevel");
            for (Field field2 : cls.getFields()) {
                if (Modifier.isStatic(field2.getModifiers()) && Modifier.isFinal(field2.getModifiers())) {
                    if (field2.getName().startsWith("AVCLevel")) {
                        mAVCLevelValues.put(field2.getInt(null), field2.getName());
                    } else if (field2.getName().startsWith("AVCProfile")) {
                        mAVCProfileValues.put(field2.getInt(null), field2.getName());
                    } else if (field2.getName().startsWith("H263Level")) {
                        mH263LevelValues.put(field2.getInt(null), field2.getName());
                    } else if (field2.getName().startsWith("H263Profile")) {
                        mH263ProfileValues.put(field2.getInt(null), field2.getName());
                    } else if (field2.getName().startsWith("MPEG4Level")) {
                        mMPEG4LevelValues.put(field2.getInt(null), field2.getName());
                    } else if (field2.getName().startsWith("MPEG4Profile")) {
                        mMPEG4ProfileValues.put(field2.getInt(null), field2.getName());
                    } else if (field2.getName().startsWith("AAC")) {
                        mAACProfileValues.put(field2.getInt(null), field2.getName());
                    }
                }
            }
            profileField = cls.getField(Scopes.PROFILE);
            levelField = cls.getField(Param.LEVEL);
        } catch (ClassNotFoundException | IllegalAccessException | IllegalArgumentException | NoSuchFieldException | NoSuchMethodException | SecurityException unused) {
        }
    }

    public static String collecMediaCodecList() {
        StringBuilder sb = new StringBuilder();
        Class<?> cls = mediaCodecListClass;
        if (!(cls == null || mediaCodecInfoClass == null)) {
            try {
                int intValue = ((Integer) cls.getMethod("getCodecCount", new Class[0]).invoke(null, new Object[0])).intValue();
                for (int i = 0; i < intValue; i++) {
                    sb.append("\n");
                    Object invoke = getCodecInfoAtMethod.invoke(null, new Object[]{Integer.valueOf(i)});
                    sb.append(i);
                    sb.append(": ");
                    sb.append(getNameMethod.invoke(invoke, new Object[0]));
                    sb.append("\n");
                    sb.append("isEncoder: ");
                    sb.append(isEncoderMethod.invoke(invoke, new Object[0]));
                    sb.append("\n");
                    String[] strArr = (String[]) getSupportedTypesMethod.invoke(invoke, new Object[0]);
                    sb.append("Supported types: ");
                    sb.append(Arrays.toString(strArr));
                    sb.append("\n");
                    for (String collectCapabilitiesForType : strArr) {
                        sb.append(collectCapabilitiesForType(invoke, collectCapabilitiesForType));
                    }
                    sb.append("\n");
                }
            } catch (IllegalAccessException | NoSuchMethodException | InvocationTargetException unused) {
            }
        }
        return sb.toString();
    }

    private static String collectCapabilitiesForType(Object obj, String str) throws IllegalArgumentException, IllegalAccessException, InvocationTargetException {
        StringBuilder sb = new StringBuilder();
        Object invoke = getCapabilitiesForTypeMethod.invoke(obj, new Object[]{str});
        int[] iArr = (int[]) colorFormatsField.get(invoke);
        if (iArr.length > 0) {
            sb.append(str);
            sb.append(" color formats:");
            for (int i = 0; i < iArr.length; i++) {
                sb.append(mColorFormatValues.get(iArr[i]));
                if (i < iArr.length - 1) {
                    sb.append(',');
                }
            }
            sb.append("\n");
        }
        Object[] objArr = (Object[]) profileLevelsField.get(invoke);
        if (objArr.length > 0) {
            sb.append(str);
            sb.append(" profile levels:");
            for (int i2 = 0; i2 < objArr.length; i2++) {
                CodecType identifyCodecType = identifyCodecType(obj);
                int i3 = profileField.getInt(objArr[i2]);
                int i4 = levelField.getInt(objArr[i2]);
                if (identifyCodecType == null) {
                    sb.append(i3);
                    sb.append('-');
                    sb.append(i4);
                }
                int i5 = AnonymousClass1.$SwitchMap$org$acra$collector$MediaCodecListCollector$CodecType[identifyCodecType.ordinal()];
                if (i5 == 1) {
                    sb.append(i3);
                    sb.append(mAVCProfileValues.get(i3));
                    sb.append('-');
                    sb.append(mAVCLevelValues.get(i4));
                } else if (i5 == 2) {
                    sb.append(mH263ProfileValues.get(i3));
                    sb.append('-');
                    sb.append(mH263LevelValues.get(i4));
                } else if (i5 == 3) {
                    sb.append(mMPEG4ProfileValues.get(i3));
                    sb.append('-');
                    sb.append(mMPEG4LevelValues.get(i4));
                } else if (i5 == 4) {
                    sb.append(mAACProfileValues.get(i3));
                }
                if (i2 < objArr.length - 1) {
                    sb.append(',');
                }
            }
            sb.append("\n");
        }
        sb.append("\n");
        return sb.toString();
    }

    private static CodecType identifyCodecType(Object obj) throws IllegalArgumentException, IllegalAccessException, InvocationTargetException {
        String str = (String) getNameMethod.invoke(obj, new Object[0]);
        for (String contains : AVC_TYPES) {
            if (str.contains(contains)) {
                return CodecType.AVC;
            }
        }
        for (String contains2 : H263_TYPES) {
            if (str.contains(contains2)) {
                return CodecType.H263;
            }
        }
        for (String contains3 : MPEG4_TYPES) {
            if (str.contains(contains3)) {
                return CodecType.MPEG4;
            }
        }
        for (String contains4 : AAC_TYPES) {
            if (str.contains(contains4)) {
                return CodecType.AAC;
            }
        }
        return null;
    }
}