package com.igaworks.util;

import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ImageView;

public class RecycleUtils {
    private RecycleUtils() {
    }

    public static void recursiveRecycle(View root) {
        if (root != null) {
            root.setBackgroundDrawable(null);
            if (root instanceof ViewGroup) {
                ViewGroup group = (ViewGroup) root;
                int count = group.getChildCount();
                for (int i = 0; i < count; i++) {
                    recursiveRecycle(group.getChildAt(i));
                }
                if (!(root instanceof AdapterView)) {
                    group.removeAllViews();
                }
            }
            if (root instanceof ImageView) {
                ((ImageView) root).setImageDrawable(null);
            }
        }
    }
}