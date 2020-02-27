package com.nuvent.shareat.observer;

import android.content.Context;
import android.database.ContentObserver;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.net.Uri;
import android.os.Handler;
import android.provider.ContactsContract.CommonDataKinds.Phone;
import com.nuvent.shareat.dao.AddressDB;
import com.nuvent.shareat.manager.AddressManager;
import com.nuvent.shareat.model.AddressModel;
import java.util.ArrayList;

public class AddressObserver extends ContentObserver {
    private Context mContext;
    private AddressDB mDBHelper;
    private SQLiteDatabase mDataBase;

    public AddressObserver(Handler handler, Context context) {
        super(handler);
        this.mContext = context;
        ArrayList<AddressModel> models = isNewAddress();
        if (models != null && models.size() > 0) {
            AddressManager.getInstance(context).synchronizedAddress();
        }
    }

    public boolean deliverSelfNotifications() {
        return super.deliverSelfNotifications();
    }

    public void onChange(boolean selfChange) {
        super.onChange(selfChange);
        ArrayList<AddressModel> models = isNewAddress();
        if (models != null && models.size() > 0) {
            AddressManager.getInstance(this.mContext).synchronizedAddress();
        }
    }

    private ArrayList<AddressModel> isNewAddress() {
        if (this.mDBHelper == null) {
            this.mDBHelper = new AddressDB(this.mContext.getApplicationContext(), "shareat_address.db", null, 3);
        }
        Uri uri = Phone.CONTENT_URI;
        this.mDataBase = this.mDBHelper.getReadableDatabase();
        Cursor cursor = this.mDataBase.query("MAXID", null, null, null, null, null, null, null);
        cursor.moveToFirst();
        String[] selection = !cursor.isAfterLast() ? new String[]{cursor.getString(0)} : new String[]{cursor.getString(0)};
        String[] projection = {"contact_id", "data1", "display_name"};
        ArrayList<AddressModel> addressModels = new ArrayList<>();
        try {
            Cursor contactCursor = this.mContext.getContentResolver().query(uri, projection, "contact_id>?", selection, null);
            if (contactCursor == null) {
                return null;
            }
            if (contactCursor.moveToFirst()) {
                while (true) {
                    if (contactCursor == null || contactCursor.getCount() <= 0) {
                        break;
                    }
                    if (contactCursor.getString(1) != null) {
                        String phonenumber = contactCursor.getString(1).replaceAll("\\-", "");
                        if (!(phonenumber == null || phonenumber == null)) {
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
        } catch (Exception e) {
            e.printStackTrace();
            return addressModels;
        }
    }
}