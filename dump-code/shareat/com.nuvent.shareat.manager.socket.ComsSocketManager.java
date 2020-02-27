package com.nuvent.shareat.manager.socket;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.IBinder;
import android.os.RemoteException;
import com.nuvent.shareat.ICommunicationService;
import com.nuvent.shareat.ICommunicationServiceCallback.Stub;
import com.nuvent.shareat.manager.app.AppSettingManager;
import com.nuvent.shareat.service.CommunicationService;
import org.json.JSONObject;

public class ComsSocketManager {
    /* access modifiers changed from: private */
    public int mConnectionStatus = 1;
    private Context mContext;
    /* access modifiers changed from: private */
    public SocketEventListener mListener;
    /* access modifiers changed from: private */
    public final Stub mServiceCallback = new Stub() {
        public void onChangeStatus(int status) throws RemoteException {
            ComsSocketManager.this.mConnectionStatus = status;
            if (ComsSocketManager.this.mListener != null) {
                ComsSocketManager.this.mListener.onChangeStatus(status);
            }
        }

        public void onChangePaymentStatus(boolean paying) throws RemoteException {
            if (ComsSocketManager.this.mListener != null) {
                ComsSocketManager.this.mListener.onChangePayingStatus(paying);
            }
        }

        public void onReceiveMessage(String method, String jsonValue) throws RemoteException {
            if (jsonValue == null || jsonValue == "") {
                ComsSocketManager.this.onMessage(method, null);
                return;
            }
            try {
                JSONObject jObj = new JSONObject(jsonValue);
                if (jObj != null) {
                    ComsSocketManager.this.onMessage(method, jObj);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    };
    private final ServiceConnection mServiceConnection = new ServiceConnection() {
        public void onServiceConnected(ComponentName componentName, IBinder iBinder) {
            ComsSocketManager.this.mSocketService = ICommunicationService.Stub.asInterface(iBinder);
            ComsSocketManager.this.mListener.onConnect();
            if (ComsSocketManager.this.mSocketService != null) {
                try {
                    ComsSocketManager.this.mSocketService.registCallback(ComsSocketManager.this.mServiceCallback);
                    ComsSocketManager.this.mConnectionStatus = ComsSocketManager.this.mSocketService.getConnectStatus();
                    ComsSocketManager.this.mSocketService.reqPaymentStatus();
                } catch (RemoteException e) {
                    e.printStackTrace();
                }
            }
        }

        public void onServiceDisconnected(ComponentName componentName) {
            ComsSocketManager.this.mListener.onDisconnect();
            if (ComsSocketManager.this.mSocketService != null) {
                try {
                    ComsSocketManager.this.mSocketService.unRegistCallback(ComsSocketManager.this.mServiceCallback);
                } catch (RemoteException e) {
                    e.printStackTrace();
                }
            }
        }
    };
    /* access modifiers changed from: private */
    public ICommunicationService mSocketService;

    public interface SocketEventListener {
        void onChangePayingStatus(boolean z);

        void onChangeStatus(int i);

        void onConnect();

        void onDisconnect();

        void onMessage(String str, JSONObject jSONObject);
    }

    public ComsSocketManager(Activity activity) {
        this.mContext = activity;
    }

    public void registServiceBind() {
        this.mContext.bindService(new Intent(this.mContext, CommunicationService.class), this.mServiceConnection, 1);
    }

    public void unRegistServiceBind() {
        if (this.mServiceConnection != null && this.mSocketService != null) {
            this.mContext.unbindService(this.mServiceConnection);
        }
    }

    public boolean isPaying() {
        if (this.mSocketService != null) {
            try {
                return this.mSocketService.isPaying();
            } catch (Exception e) {
            }
        }
        return false;
    }

    public void sendMessage(String method, String parameter) {
        if (this.mSocketService != null) {
            try {
                this.mSocketService.sendMessage(method, parameter);
            } catch (RemoteException e) {
                e.printStackTrace();
            }
        }
    }

    public void setSocketUrl(String url) {
        AppSettingManager.getInstance().setSocketUrl(url);
        if (this.mSocketService != null) {
            try {
                this.mSocketService.changeSocketUrl();
            } catch (RemoteException e) {
                e.printStackTrace();
            }
        }
    }

    public void sendMessage(String method, JSONObject parameter) {
        sendMessage(method, parameter.toString());
    }

    /* access modifiers changed from: private */
    public void onMessage(String method, JSONObject parameter) {
        this.mListener.onMessage(method, parameter);
    }

    public void setSocketEventListener(SocketEventListener listener) {
        this.mListener = listener;
    }
}