package org.acra.collector;

import android.content.Context;
import android.graphics.Point;
import android.graphics.Rect;
import android.util.DisplayMetrics;
import android.util.SparseArray;
import android.view.Display;
import android.view.WindowManager;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import org.acra.ACRA;

final class DisplayManagerCollector {
    static final SparseArray<String> mDensities = new SparseArray<>();
    static final SparseArray<String> mFlagsNames = new SparseArray<>();

    DisplayManagerCollector() {
    }

    public static String collectDisplays(Context context) {
        StringBuilder sb = new StringBuilder();
        Display[] displayArr = null;
        if (Compatibility.getAPILevel() < 17) {
            displayArr = new Display[]{((WindowManager) context.getSystemService("window")).getDefaultDisplay()};
        } else {
            try {
                Object systemService = context.getSystemService((String) context.getClass().getField("DISPLAY_SERVICE").get(null));
                displayArr = (Display[]) systemService.getClass().getMethod("getDisplays", new Class[0]).invoke(systemService, new Object[0]);
            } catch (IllegalArgumentException e) {
                ACRA.log.w(ACRA.LOG_TAG, "Error while collecting DisplayManager data: ", e);
            } catch (SecurityException e2) {
                ACRA.log.w(ACRA.LOG_TAG, "Error while collecting DisplayManager data: ", e2);
            } catch (IllegalAccessException e3) {
                ACRA.log.w(ACRA.LOG_TAG, "Error while collecting DisplayManager data: ", e3);
            } catch (NoSuchFieldException e4) {
                ACRA.log.w(ACRA.LOG_TAG, "Error while collecting DisplayManager data: ", e4);
            } catch (NoSuchMethodException e5) {
                ACRA.log.w(ACRA.LOG_TAG, "Error while collecting DisplayManager data: ", e5);
            } catch (InvocationTargetException e6) {
                ACRA.log.w(ACRA.LOG_TAG, "Error while collecting DisplayManager data: ", e6);
            }
        }
        for (Display collectDisplayData : displayArr) {
            sb.append(collectDisplayData(collectDisplayData));
        }
        return sb.toString();
    }

    private static Object collectDisplayData(Display display) {
        display.getMetrics(new DisplayMetrics());
        StringBuilder sb = new StringBuilder();
        sb.append(collectCurrentSizeRange(display));
        sb.append(collectFlags(display));
        sb.append(display.getDisplayId());
        sb.append(".height=");
        sb.append(display.getHeight());
        sb.append(10);
        sb.append(collectMetrics(display, "getMetrics"));
        sb.append(collectName(display));
        sb.append(display.getDisplayId());
        sb.append(".orientation=");
        sb.append(display.getOrientation());
        sb.append(10);
        sb.append(display.getDisplayId());
        sb.append(".pixelFormat=");
        sb.append(display.getPixelFormat());
        sb.append(10);
        sb.append(collectMetrics(display, "getRealMetrics"));
        sb.append(collectSize(display, "getRealSize"));
        sb.append(collectRectSize(display));
        sb.append(display.getDisplayId());
        sb.append(".refreshRate=");
        sb.append(display.getRefreshRate());
        sb.append(10);
        sb.append(collectRotation(display));
        sb.append(collectSize(display, "getSize"));
        sb.append(display.getDisplayId());
        sb.append(".width=");
        sb.append(display.getWidth());
        sb.append(10);
        sb.append(collectIsValid(display));
        return sb.toString();
    }

    private static Object collectIsValid(Display display) {
        StringBuilder sb = new StringBuilder();
        try {
            sb.append(display.getDisplayId());
            sb.append(".isValid=");
            sb.append((Boolean) display.getClass().getMethod("isValid", new Class[0]).invoke(display, new Object[0]));
            sb.append(10);
        } catch (IllegalAccessException | IllegalArgumentException | NoSuchMethodException | SecurityException | InvocationTargetException unused) {
        }
        return sb.toString();
    }

    private static Object collectRotation(Display display) {
        StringBuilder sb = new StringBuilder();
        try {
            int intValue = ((Integer) display.getClass().getMethod("getRotation", new Class[0]).invoke(display, new Object[0])).intValue();
            sb.append(display.getDisplayId());
            sb.append(".rotation=");
            if (intValue == 0) {
                sb.append("ROTATION_0");
            } else if (intValue == 1) {
                sb.append("ROTATION_90");
            } else if (intValue == 2) {
                sb.append("ROTATION_180");
            } else if (intValue != 3) {
                sb.append(intValue);
            } else {
                sb.append("ROTATION_270");
            }
            sb.append(10);
        } catch (IllegalAccessException | IllegalArgumentException | NoSuchMethodException | SecurityException | InvocationTargetException unused) {
        }
        return sb.toString();
    }

    private static Object collectRectSize(Display display) {
        StringBuilder sb = new StringBuilder();
        try {
            Method method = display.getClass().getMethod("getRectSize", new Class[]{Rect.class});
            Rect rect = new Rect();
            method.invoke(display, new Object[]{rect});
            sb.append(display.getDisplayId());
            sb.append(".rectSize=[");
            sb.append(rect.top);
            sb.append(',');
            sb.append(rect.left);
            sb.append(',');
            sb.append(rect.width());
            sb.append(',');
            sb.append(rect.height());
            sb.append(']');
            sb.append(10);
        } catch (IllegalAccessException | IllegalArgumentException | NoSuchMethodException | SecurityException | InvocationTargetException unused) {
        }
        return sb.toString();
    }

    private static Object collectSize(Display display, String str) {
        StringBuilder sb = new StringBuilder();
        try {
            Method method = display.getClass().getMethod(str, new Class[]{Point.class});
            Point point = new Point();
            method.invoke(display, new Object[]{point});
            sb.append(display.getDisplayId());
            sb.append('.');
            sb.append(str);
            sb.append("=[");
            sb.append(point.x);
            sb.append(',');
            sb.append(point.y);
            sb.append(']');
            sb.append(10);
        } catch (IllegalAccessException | IllegalArgumentException | NoSuchMethodException | SecurityException | InvocationTargetException unused) {
        }
        return sb.toString();
    }

    private static String collectCurrentSizeRange(Display display) {
        StringBuilder sb = new StringBuilder();
        try {
            Method method = display.getClass().getMethod("getCurrentSizeRange", new Class[]{Point.class, Point.class});
            Point point = new Point();
            Point point2 = new Point();
            method.invoke(display, new Object[]{point, point2});
            sb.append(display.getDisplayId());
            sb.append(".currentSizeRange.smallest=[");
            sb.append(point.x);
            sb.append(',');
            sb.append(point.y);
            sb.append(']');
            sb.append(10);
            sb.append(display.getDisplayId());
            sb.append(".currentSizeRange.largest=[");
            sb.append(point2.x);
            sb.append(',');
            sb.append(point2.y);
            sb.append(']');
            sb.append(10);
        } catch (IllegalAccessException | IllegalArgumentException | NoSuchMethodException | SecurityException | InvocationTargetException unused) {
        }
        return sb.toString();
    }

    private static String collectFlags(Display display) {
        Field[] fields;
        StringBuilder sb = new StringBuilder();
        try {
            int intValue = ((Integer) display.getClass().getMethod("getFlags", new Class[0]).invoke(display, new Object[0])).intValue();
            for (Field field : display.getClass().getFields()) {
                if (field.getName().startsWith("FLAG_")) {
                    mFlagsNames.put(field.getInt(null), field.getName());
                }
            }
            sb.append(display.getDisplayId());
            sb.append(".flags=");
            sb.append(activeFlags(mFlagsNames, intValue));
            sb.append(10);
        } catch (IllegalAccessException | IllegalArgumentException | NoSuchMethodException | SecurityException | InvocationTargetException unused) {
        }
        return sb.toString();
    }

    private static String collectName(Display display) {
        StringBuilder sb = new StringBuilder();
        try {
            sb.append(display.getDisplayId());
            sb.append(".name=");
            sb.append((String) display.getClass().getMethod("getName", new Class[0]).invoke(display, new Object[0]));
            sb.append(10);
        } catch (IllegalAccessException | IllegalArgumentException | NoSuchMethodException | SecurityException | InvocationTargetException unused) {
        }
        return sb.toString();
    }

    private static Object collectMetrics(Display display, String str) {
        Field[] fields;
        StringBuilder sb = new StringBuilder();
        try {
            DisplayMetrics displayMetrics = (DisplayMetrics) display.getClass().getMethod(str, new Class[0]).invoke(display, new Object[0]);
            for (Field field : DisplayMetrics.class.getFields()) {
                if (field.getType().equals(Integer.class) && field.getName().startsWith("DENSITY_") && !field.getName().equals("DENSITY_DEFAULT")) {
                    mDensities.put(field.getInt(null), field.getName());
                }
            }
            sb.append(display.getDisplayId());
            sb.append('.');
            sb.append(str);
            sb.append(".density=");
            sb.append(displayMetrics.density);
            sb.append(10);
            sb.append(display.getDisplayId());
            sb.append('.');
            sb.append(str);
            sb.append(".densityDpi=");
            sb.append(displayMetrics.getClass().getField("densityDpi"));
            sb.append(10);
            sb.append(display.getDisplayId());
            sb.append('.');
            sb.append(str);
            sb.append("scaledDensity=x");
            sb.append(displayMetrics.scaledDensity);
            sb.append(10);
            sb.append(display.getDisplayId());
            sb.append('.');
            sb.append(str);
            sb.append(".widthPixels=");
            sb.append(displayMetrics.widthPixels);
            sb.append(10);
            sb.append(display.getDisplayId());
            sb.append('.');
            sb.append(str);
            sb.append(".heightPixels=");
            sb.append(displayMetrics.heightPixels);
            sb.append(10);
            sb.append(display.getDisplayId());
            sb.append('.');
            sb.append(str);
            sb.append(".xdpi=");
            sb.append(displayMetrics.xdpi);
            sb.append(10);
            sb.append(display.getDisplayId());
            sb.append('.');
            sb.append(str);
            sb.append(".ydpi=");
            sb.append(displayMetrics.ydpi);
            sb.append(10);
        } catch (IllegalAccessException | IllegalArgumentException | NoSuchFieldException | NoSuchMethodException | SecurityException | InvocationTargetException unused) {
        }
        return sb.toString();
    }

    private static String activeFlags(SparseArray<String> sparseArray, int i) {
        StringBuilder sb = new StringBuilder();
        for (int i2 = 0; i2 < sparseArray.size(); i2++) {
            int keyAt = sparseArray.keyAt(i2) & i;
            if (keyAt > 0) {
                if (sb.length() > 0) {
                    sb.append('+');
                }
                sb.append(sparseArray.get(keyAt));
            }
        }
        return sb.toString();
    }
}