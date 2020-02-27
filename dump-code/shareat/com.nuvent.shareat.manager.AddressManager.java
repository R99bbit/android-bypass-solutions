package com.nuvent.shareat.manager;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.provider.ContactsContract.CommonDataKinds.Phone;
import com.facebook.appevents.AppEventsConstants;
import com.google.gson.GsonBuilder;
import com.kakao.kakaolink.internal.KakaoTalkLinkProtocol;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.friend.AddressRegistApi;
import com.nuvent.shareat.dao.AddressDB;
import com.nuvent.shareat.event.AddressStateEvent;
import com.nuvent.shareat.model.AddressModel;
import com.nuvent.shareat.model.friend.FriendModel;
import com.nuvent.shareat.model.friend.FriendResultModel;
import de.greenrobot.event.EventBus;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;

public class AddressManager {
    public static final int STATE_COMPLETE = 3;
    public static final int STATE_IDLE = 1;
    public static final int STATE_PROCESS = 2;
    private static AddressManager mInstance;
    private Context mContext;
    private AddressDB mDBHelper;
    private SQLiteDatabase mDataBase;
    private int mObserverState;

    static class NameAscCompare implements Comparator<FriendModel> {
        NameAscCompare() {
        }

        public int compare(FriendModel arg0, FriendModel arg1) {
            return arg0.getUser_name().compareTo(arg1.getUser_name());
        }
    }

    public AddressManager(Context context) {
        this.mContext = context;
        if (this.mDBHelper == null) {
            this.mDBHelper = new AddressDB(this.mContext.getApplicationContext(), "shareat_address.db", null, 3);
        }
    }

    public synchronized void synchronizedAddress() {
        if (this.mObserverState != 2) {
            this.mObserverState = 2;
        }
        ArrayList<AddressModel> addressModels = getPhoneAddress();
        long currentTime = System.currentTimeMillis();
        insertAddress(addressModels, currentTime);
        ArrayList<AddressModel> models = getNewAddress(currentTime);
        if (models.size() > 0) {
            String arrayListToJson = new GsonBuilder().create().toJson((Object) models);
            AddressRegistApi request = new AddressRegistApi(this.mContext);
            request.addParam("page", AppEventsConstants.EVENT_PARAM_VALUE_YES);
            request.addParam("view_cnt", String.valueOf(models.size()));
            request.addParam("contacts", arrayListToJson);
            request.request(new RequestHandler() {
                public void onStart() {
                    super.onStart();
                }

                public void onProgress(int bytesWritten, int totalSize) {
                    super.onProgress(bytesWritten, totalSize);
                }

                public void onResult(Object result) {
                    FriendResultModel model = (FriendResultModel) result;
                    if (model.getResult().equals("Y")) {
                        AddressManager.this.insertUserAddress(model.getResult_list());
                        AddressManager.this.getAllDBAddress();
                    }
                }

                public void onFailure(Exception exception) {
                    super.onFailure(exception);
                }

                public void onFinish() {
                    super.onFinish();
                }
            });
        }
    }

    public void getAllDBAddress() {
        ArrayList<FriendModel> tempModels = new ArrayList<>();
        ArrayList<FriendModel> models = new ArrayList<>();
        this.mDataBase = this.mDBHelper.getReadableDatabase();
        Cursor cursor = this.mDataBase.rawQuery("SELECT * FROM ADDRESS LEFT OUTER JOIN USER ON ADDRESS.phone = USER.phone ORDER BY USER.user_sno DESC, ADDRESS.name ASC", null);
        if (cursor.moveToFirst()) {
            do {
                FriendModel model = new FriendModel();
                model.setUser_phone(cursor.getString(0));
                model.setName(cursor.getString(1));
                model.setUser_name(cursor.getString(5));
                model.setUser_img(cursor.getString(9));
                model.setUser_sno(cursor.getString(10));
                model.setFollow_status(cursor.getString(7));
                model.setFollow_status_text(cursor.getString(8));
                if (model.getUser_sno() == null || model.getUser_sno().isEmpty()) {
                    models.add(model);
                } else {
                    tempModels.add(model);
                }
            } while (cursor.moveToNext());
        }
        this.mDataBase.close();
        this.mObserverState = 3;
        Collections.sort(tempModels, new NameAscCompare());
        models.addAll(0, tempModels);
        EventBus.getDefault().post(new AddressStateEvent(this.mObserverState, models));
        this.mObserverState = 1;
    }

    public void insertUserAddress(ArrayList<FriendModel> models) {
        this.mDataBase = this.mDBHelper.getWritableDatabase();
        this.mDataBase.beginTransaction();
        try {
            Iterator<FriendModel> it = models.iterator();
            while (it.hasNext()) {
                FriendModel addressModel = it.next();
                ContentValues values = new ContentValues();
                values.put("phone", addressModel.getUser_phone());
                values.put("user_name", addressModel.getUser_name());
                values.put(KakaoTalkLinkProtocol.ACTION_TYPE, AppEventsConstants.EVENT_PARAM_VALUE_YES);
                values.put("status", addressModel.getFollow_status());
                values.put("text", addressModel.getFollow_status_text());
                values.put("user_image", addressModel.getUser_img());
                values.put("user_sno", addressModel.getUser_sno());
                this.mDataBase.insertWithOnConflict("USER", null, values, 4);
            }
            this.mDataBase.setTransactionSuccessful();
        } finally {
            this.mDataBase.endTransaction();
            this.mDataBase.close();
        }
    }

    public ArrayList<FriendModel> getAllAddress() {
        this.mDataBase = this.mDBHelper.getReadableDatabase();
        ArrayList<FriendModel> models = new ArrayList<>();
        Cursor cursor = this.mDataBase.rawQuery("select * from ADDRESS", null);
        while (cursor.moveToNext()) {
            FriendModel model = new FriendModel();
            model.setUser_phone(cursor.getString(0));
            model.setUser_name(cursor.getString(1));
            models.add(model);
        }
        this.mDBHelper.close();
        this.mDataBase.close();
        return models;
    }

    public static AddressManager getInstance(Context context) {
        if (mInstance == null) {
            mInstance = new AddressManager(context);
        }
        return mInstance;
    }

    public void startObserver() {
    }

    public void setObserverState(int state) {
        if (this.mObserverState != 2) {
            this.mObserverState = state;
        }
    }

    public int getObserverState() {
        return this.mObserverState;
    }

    public void setAddressApi() {
    }

    private void insertAddress(ArrayList<AddressModel> models, long time) {
        SQLiteDatabase dataBase = this.mDBHelper.getWritableDatabase();
        dataBase.beginTransaction();
        try {
            Iterator<AddressModel> it = models.iterator();
            while (it.hasNext()) {
                AddressModel model = it.next();
                ContentValues values = new ContentValues();
                values.put("phone", model.getPhonenum().replace("-", ""));
                values.put("name", model.getName());
                values.put("id", model.getId());
                values.put("timestamp", Long.valueOf(time));
                dataBase.insertWithOnConflict("ADDRESS", null, values, 4);
            }
            dataBase.setTransactionSuccessful();
        } finally {
            dataBase.endTransaction();
            dataBase.close();
        }
    }

    /* JADX INFO: finally extract failed */
    public void updateAddress(ArrayList<FriendModel> models) {
        if (this.mObserverState != 2) {
            this.mObserverState = 2;
        }
        SQLiteDatabase dataBase = this.mDBHelper.getWritableDatabase();
        dataBase.beginTransaction();
        try {
            Iterator<FriendModel> it = models.iterator();
            while (it.hasNext()) {
                FriendModel model = it.next();
                ContentValues values = new ContentValues();
                values.put("status", model.getFollow_status());
                values.put("text", model.getFollow_status_text());
                values.put("user_name", model.getUser_name());
                values.put("user_image", model.getUser_img());
                values.put("user_sno", model.getUser_sno());
                dataBase.update("USER", values, "phone=?", new String[]{model.getUser_phone()});
            }
            dataBase.setTransactionSuccessful();
            dataBase.endTransaction();
            dataBase.close();
            getAllDBAddress();
        } catch (Throwable th) {
            dataBase.endTransaction();
            dataBase.close();
            throw th;
        }
    }

    public ArrayList<AddressModel> getNewAddress(long time) {
        ArrayList<AddressModel> addressModels = new ArrayList<>();
        SQLiteDatabase dataBase = this.mDBHelper.getReadableDatabase();
        Cursor cursor = dataBase.query("ADDRESS", null, "timestamp=?", new String[]{String.valueOf(time)}, null, null, null);
        cursor.moveToFirst();
        while (!cursor.isAfterLast()) {
            AddressModel model = new AddressModel();
            String phone = cursor.getString(0);
            String name = cursor.getString(1);
            model.setPhonenum(phone);
            model.setName(name);
            addressModels.add(model);
            cursor.moveToNext();
        }
        cursor.close();
        dataBase.close();
        return addressModels;
    }

    public ArrayList<AddressModel> getPhoneAddress() {
        Cursor contactCursor = this.mContext.getContentResolver().query(Phone.CONTENT_URI, new String[]{"contact_id", "data1", "display_name"}, null, null, null);
        ArrayList<AddressModel> addressModels = new ArrayList<>();
        if (contactCursor.moveToFirst()) {
            while (contactCursor != null && contactCursor.getCount() > 0) {
                if (contactCursor.getString(1) != null) {
                    String phonenumber = contactCursor.getString(1).replaceAll("\\-", "");
                    if (phonenumber != null) {
                        if (phonenumber.length() == 10) {
                            phonenumber = phonenumber.substring(0, 3) + "-" + phonenumber.substring(3, 6) + "-" + phonenumber.substring(6);
                        } else if (phonenumber.length() > 8) {
                            phonenumber = phonenumber.substring(0, 3) + "-" + phonenumber.substring(3, 7) + "-" + phonenumber.substring(7);
                        }
                        AddressModel addressModel = new AddressModel();
                        addressModel.setPhonenum(phonenumber);
                        addressModel.setName(contactCursor.getString(2));
                        addressModel.setId(contactCursor.getString(0));
                        addressModels.add(addressModel);
                    }
                }
                if (!contactCursor.moveToNext()) {
                    break;
                }
            }
        }
        contactCursor.close();
        return addressModels;
    }
}