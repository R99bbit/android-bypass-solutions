package com.igaworks.adbrix.util;

import android.content.Context;
import android.util.TypedValue;
import android.widget.TextView;

public class CPEConstant {
    public static final float BASE_HEIGHT = 800.0f;
    public static final float BASE_WIDTH = 480.0f;
    public static final String CLOSE_BTN = "http://static.adbrix.igaworks.com/adbrix_res/sdk_res/popup_close_bt.png";
    public static final int DIALOG_AD_IMG_SECTION_PADDING = 4;
    public static final int DIALOG_AD_IMG_TITLE_MARGIN = 4;
    public static final int DIALOG_CLOSE_BTN_SIZE = 40;
    public static final int DIALOG_DIVIDER_HEIGHT = 1;
    public static final int DIALOG_MAIN_PADDING = 10;
    public static final int DIALOG_MARGIN = 10;
    public static final int DIALOG_NEXT_ARROW_SIZE = 14;
    public static final int DIALOG_ONE_STEP_DESC_LL_PADDING = 10;
    public static final int DIALOG_ONE_STEP_ITEM_HEIGHT_LANDSCAPE = 38;
    public static final int DIALOG_ONE_STEP_ITEM_HEIGHT_PORTRAIT = 38;
    public static final int DIALOG_ONE_STEP_MARGIN_ITEM = 2;
    public static final int DIALOG_ONE_STEP_TV_ROUND_LANDSCAPE = 18;
    public static final int DIALOG_ONE_STEP_TV_ROUND_PORTRAIT = 18;
    public static final int DIALOG_ONE_STEP_TV_TEXT_SIZE = 13;
    public static final int DIALOG_PLAY_BTN_HEIGHT_PORTRAIT = 80;
    public static final int DIALOG_PLAY_BTN_LL_PADDING_LANDSCAPE = 10;
    public static final int DIALOG_PLAY_BTN_LL_PADDING_PORTRAIT = 5;
    public static final int DIALOG_REWARD_HEIGHT_PORTRAIT = 178;
    public static final int DIALOG_REWARD_IV_MINIMUM_WIDTH = 20;
    public static final int DIALOG_ROUND_DEGREE = 13;
    public static final int DIALOG_STEP_REWARD_COLUMN_MARGIN = 7;
    public static final int DIALOG_STEP_REWARD_ROW_PADDING = 5;
    public static final int DIALOG_STEP_TITLE_TEXT_SIZE = 15;
    public static final int DIALOG_THUMBNAIL_ARROW_SIZE = 8;
    public static final int DIALOG_THUMBNAIL_BORDER_WIDTH = 4;
    public static final int DIALOG_THUMBNAIL_ITEM_MARGIN_LANDSCAPE = 12;
    public static final int DIALOG_THUMBNAIL_ITEM_MARGIN_PORTRAIT = 6;
    public static final int DIALOG_THUMBNAIL_ITEM_SIZE = 70;
    public static final int DIALOG_THUMBNAIL_LIST_PADDING = 10;
    public static final int DIALOG_THUMBNAIL_ROUND = 14;
    public static final int DIALOG_TITLE_SIZE = 20;
    public static final int DIALOG_TITLE_SIZE_WITH_ICONS = 18;
    public static final String FIRST_UNIT_BG_COLOR_FOR_ONE_STEP = "#24e6e8";
    public static final String MISSION_CHECK_OFF = "http://static.adbrix.igaworks.com/adbrix_res/sdk_res/mission_check_off.png";
    public static final String MISSION_CHECK_ON = "http://static.adbrix.igaworks.com/adbrix_res/sdk_res/mission_check_on.png";
    public static final int NOT_AVAILABLE_CAMPAIGN = 13;
    public static final int PAGE_INDICATOR_RADIUS = 6;
    public static final int PAGE_INDICATOR_STROKE_WIDTH = 1;
    public static final String PLAY_BTN_AREA_BG = "http://static.adbrix.igaworks.com/adbrix_res/sdk_res/bg_pt.png";
    public static final int PLAY_BTN_AREA_BG_SIZE = 25;
    public static final String PLAY_BTN_CIRCLE = "http://static.adbrix.igaworks.com/adbrix_res/sdk_res/play_bt_circle.png";
    public static final String PLAY_BTN_SQUARE = "http://static.adbrix.igaworks.com/adbrix_res/sdk_res/play_bt_square.png";
    public static final String REWARD_UNIT_BG_COLOR_FOR_ONE_STEP = "#fbd348";
    public static final String SECOND_UNIT_BG_COLOR_FOR_ONE_STEP = "#24e6e8";
    public static final String SELECTED_APP_ARROW = "http://static.adbrix.igaworks.com/adbrix_res/sdk_res/app_select_arrow.png";
    public static final String SLIDE_LEFT_BTN = "http://static.adbrix.igaworks.com/adbrix_res/sdk_res/img_slide_left.png";
    public static final String SLIDE_RIGHT_BTN = "http://static.adbrix.igaworks.com/adbrix_res/sdk_res/img_slide_right.png";
    public static final String STEP_ARROW = "http://static.adbrix.igaworks.com/adbrix_res/sdk_res/step_arrow.png";
    public static final int WINDOW_PADDING = 10;

    public static int calculateTextSize(Context context, float target) {
        return (int) TypedValue.applyDimension(2, target, context.getResources().getDisplayMetrics());
    }

    public static int calculateDpSize(Context context, float target) {
        return (int) TypedValue.applyDimension(1, target, context.getResources().getDisplayMetrics());
    }

    public static int convertPixelToDP(Context context, int px, boolean isX) {
        float norPx;
        int width = context.getResources().getDisplayMetrics().widthPixels;
        int height = context.getResources().getDisplayMetrics().heightPixels;
        if (context.getResources().getConfiguration().orientation == 2) {
            width = context.getResources().getDisplayMetrics().heightPixels;
            height = context.getResources().getDisplayMetrics().widthPixels;
        }
        float difX = ((float) width) / 480.0f;
        float difY = ((float) height) / 800.0f;
        if (difX != difY) {
            difY = difX;
        }
        float f = (float) px;
        if (isX) {
            norPx = ((float) px) * difX;
        } else {
            norPx = ((float) px) * difY;
        }
        if (norPx < 1.5f) {
            norPx = 1.5f;
        }
        return (int) TypedValue.applyDimension(0, norPx, context.getResources().getDisplayMetrics());
    }

    public static void setTextViewSize(Context context, TextView tv, int size) {
        tv.setTextSize(0, (float) calNormPixel(context, size, false));
    }

    public static int calNormPixel(Context context, int px, boolean isX) {
        int width = context.getResources().getDisplayMetrics().widthPixels;
        int height = context.getResources().getDisplayMetrics().heightPixels;
        if (context.getResources().getConfiguration().orientation == 2) {
            width = context.getResources().getDisplayMetrics().heightPixels;
            height = context.getResources().getDisplayMetrics().widthPixels;
        }
        float difX = ((float) width) / 480.0f;
        if (difX != ((float) height) / 800.0f) {
            float difY = difX;
        }
        int i = px;
        if (isX) {
            return (int) (((float) (px * width)) / 480.0f);
        }
        return (int) (((float) (px * height)) / 800.0f);
    }
}