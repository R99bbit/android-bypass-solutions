package com.embrain.panelpower.utils;

import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import com.embrain.panelbigdata.utils.StringUtils;
import com.embrain.panelpower.UserInfoManager;
import com.embrain.panelpower.networks.HttpManager;
import com.embrain.panelpower.networks.vo.LoginVo.Builder;
import com.embrain.panelpower.networks.vo.ResponseLogin;
import com.google.gson.Gson;
import java.io.IOException;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;

public class UtilDatabase {
    private static final String COL_PANEL_ID = "panel_id";
    private static final String COL_USER_ID = "user_id";
    private static final String COL_USER_PW = "user_pw";
    private static final String DATABASE_NAME_NEW = "panelpower_new.db";
    private static final int DATABASE_VERSION_NEW = 2;
    private static final String PREF_FCM_TOKEN = "pref_fcm_token";
    private static final String PREF_NAME = "com.embrain.panelpower.pref";
    /* access modifiers changed from: private */
    public static Context mContext = null;
    /* access modifiers changed from: private */
    public static OldUserInfoListener mListener = null;
    /* access modifiers changed from: private */
    public static boolean upgrade = false;

    public interface OldUserInfoListener {
        void complete();

        void findUserInfo();
    }

    private static class PanelDBOpenHelper extends SQLiteOpenHelper {
        public void onCreate(SQLiteDatabase sQLiteDatabase) {
        }

        public PanelDBOpenHelper(Context context) {
            super(context, "panelpower_new.db", null, 2);
        }

        public void onUpgrade(SQLiteDatabase sQLiteDatabase, int i, int i2) {
            UtilDatabase.upgrade = true;
            UtilDatabase.moveUserInfo(sQLiteDatabase);
        }
    }

    public static void checkOldDB(Context context, OldUserInfoListener oldUserInfoListener) {
        mContext = context;
        mListener = oldUserInfoListener;
        if (new PanelDBOpenHelper(context).getWritableDatabase().getVersion() == 2 && !upgrade) {
            mListener.complete();
        }
    }

    /* JADX WARNING: Code restructure failed: missing block: B:20:0x007e, code lost:
        if (r5.isClosed() == false) goto L_0x0080;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:21:0x0080, code lost:
        r5.close();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:28:0x0090, code lost:
        if (r5.isClosed() == false) goto L_0x0080;
     */
    public static void moveUserInfo(SQLiteDatabase sQLiteDatabase) {
        if (sQLiteDatabase != null) {
            Cursor rawQuery = sQLiteDatabase.rawQuery("SELECT user_id, user_pw, panel_id from TB_USER_INFORMATION limit 1; ", null);
            try {
                if (rawQuery.moveToFirst() && rawQuery.getCount() != 0) {
                    String string = rawQuery.getString(rawQuery.getColumnIndex(COL_USER_ID));
                    final String string2 = rawQuery.getString(rawQuery.getColumnIndex(COL_USER_PW));
                    if (StringUtils.isEmpty(string) || StringUtils.isEmpty(string2)) {
                        mListener.complete();
                        if (rawQuery != null && !rawQuery.isClosed()) {
                            rawQuery.close();
                        }
                        return;
                    }
                    mListener.findUserInfo();
                    HttpManager.getInstance().requestLogin(new Builder(string, string2, mContext.getSharedPreferences(PREF_NAME, 0).getString(PREF_FCM_TOKEN, "")).setSubinfo(mContext).build(), new Callback() {
                        public void onFailure(Call call, IOException iOException) {
                        }

                        public void onResponse(Call call, Response response) throws IOException {
                            try {
                                ResponseLogin responseLogin = (ResponseLogin) new Gson().fromJson(response.body().string(), ResponseLogin.class);
                                if (responseLogin.isSuccess()) {
                                    UserInfoManager.getInstance(UtilDatabase.mContext).saveUserInfo(responseLogin.getSession(), string2);
                                }
                            } catch (Exception e) {
                                e.printStackTrace();
                            } catch (Throwable th) {
                                UtilDatabase.mListener.complete();
                                throw th;
                            }
                            UtilDatabase.mListener.complete();
                        }
                    });
                }
                if (rawQuery != null) {
                }
            } catch (Exception e) {
                e.printStackTrace();
                if (rawQuery != null) {
                }
            } catch (Throwable th) {
                if (rawQuery != null && !rawQuery.isClosed()) {
                    rawQuery.close();
                }
                throw th;
            }
        } else {
            LogUtil.write("[UDB]===========[getLoginUserInfor]>>>>>>>>>> is null... ");
        }
    }
}