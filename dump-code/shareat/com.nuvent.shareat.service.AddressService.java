package com.nuvent.shareat.service;

import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.res.AssetManager;
import android.os.Handler;
import android.os.IBinder;
import android.provider.ContactsContract.RawContacts;
import android.support.annotation.Nullable;
import android.util.Log;
import com.facebook.appevents.AppEventsConstants;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.friend.AddressListApi;
import com.nuvent.shareat.manager.AddressManager;
import com.nuvent.shareat.model.friend.FriendResultModel;
import com.nuvent.shareat.observer.AddressObserver;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class AddressService extends Service {
    @Nullable
    public IBinder onBind(Intent intent) {
        updateAddress();
        return null;
    }

    public void onCreate() {
        super.onCreate();
        copyDB(getApplicationContext());
        getApplicationContext().getContentResolver().registerContentObserver(RawContacts.CONTENT_URI, false, new AddressObserver(new Handler(), getApplicationContext()));
    }

    public void copyDB(Context context) {
        AssetManager manager = context.getAssets();
        File file = getApplicationContext().getDatabasePath("shareat_address.db");
        try {
            if (!file.exists()) {
                file.getParentFile().mkdir();
                file.createNewFile();
                try {
                    InputStream is = manager.open("shareat_address.db", 3);
                    BufferedInputStream bis = new BufferedInputStream(is);
                    if (file.exists()) {
                        file.delete();
                        file.createNewFile();
                    }
                    FileOutputStream fos = new FileOutputStream(file);
                    try {
                        BufferedOutputStream bos = new BufferedOutputStream(fos);
                        try {
                            byte[] buffer = new byte[1024];
                            while (true) {
                                int read = bis.read(buffer, 0, 1024);
                                if (read != -1) {
                                    bos.write(buffer, 0, read);
                                } else {
                                    bos.flush();
                                    bos.close();
                                    fos.close();
                                    bis.close();
                                    is.close();
                                    return;
                                }
                            }
                        } catch (IOException e) {
                            e = e;
                            BufferedOutputStream bufferedOutputStream = bos;
                            FileOutputStream fileOutputStream = fos;
                        }
                    } catch (IOException e2) {
                        e = e2;
                        FileOutputStream fileOutputStream2 = fos;
                        Log.e("ErrorMessage : ", e.getMessage());
                    }
                } catch (IOException e3) {
                    e = e3;
                    Log.e("ErrorMessage : ", e.getMessage());
                }
            }
        } catch (IOException e1) {
            e1.printStackTrace();
        }
    }

    public void updateAddress() {
        AddressListApi request = new AddressListApi(getApplicationContext());
        request.addParam("page", AppEventsConstants.EVENT_PARAM_VALUE_YES);
        request.request(new RequestHandler() {
            public void onStart() {
                super.onStart();
            }

            public void onProgress(int bytesWritten, int totalSize) {
                super.onProgress(bytesWritten, totalSize);
            }

            public void onResult(Object result) {
                FriendResultModel model = (FriendResultModel) result;
                if (model.getResult().equals("Y") && model.getResult_list().size() > 0) {
                    AddressManager.getInstance(AddressService.this.getApplicationContext()).insertUserAddress(model.getResult_list());
                    AddressManager.getInstance(AddressService.this.getApplicationContext()).updateAddress(model.getResult_list());
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

    public void onDestroy() {
        super.onDestroy();
    }
}