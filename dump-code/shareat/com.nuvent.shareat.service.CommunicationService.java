package com.nuvent.shareat.service;

import android.app.Service;
import android.content.Intent;
import android.os.Handler;
import android.os.IBinder;
import android.os.RemoteCallbackList;
import android.os.RemoteException;
import android.support.annotation.Nullable;
import com.github.nkzawa.emitter.Emitter.Listener;
import com.github.nkzawa.socketio.client.IO;
import com.github.nkzawa.socketio.client.IO.Options;
import com.github.nkzawa.socketio.client.Socket;
import com.nuvent.shareat.ICommunicationService.Stub;
import com.nuvent.shareat.ICommunicationServiceCallback;
import com.nuvent.shareat.manager.app.AppSettingManager;
import com.nuvent.shareat.manager.app.SessionManager;
import com.nuvent.shareat.manager.socket.SocketInterface;
import java.net.URI;
import org.json.JSONObject;

public class CommunicationService extends Service {
    public static final int STATUS_CONNECTED = 2;
    public static final int STATUS_DISCONNECT = 3;
    public static final int STATUS_NONE = 1;
    /* access modifiers changed from: private */
    public RemoteCallbackList<ICommunicationServiceCallback> callbackList;
    private final Stub communicationServiceBinder = new Stub() {
        public void registCallback(ICommunicationServiceCallback callback) throws RemoteException {
            CommunicationService.this.callbackList.register(callback);
        }

        public void unRegistCallback(ICommunicationServiceCallback callback) throws RemoteException {
            CommunicationService.this.callbackList.unregister(callback);
        }

        public void sendMessage(String method, String parameter) throws RemoteException {
            if (method.equals("endPay")) {
                CommunicationService.this.setPaying(false);
            } else if (CommunicationService.this.connectionStatus == 2) {
                try {
                    CommunicationService.this.communicationSocket.emit(method, new JSONObject(parameter));
                    if (SocketInterface.METHOD_CUSTOMER_PAY_REQUEST_STATUS.equals(method)) {
                        CommunicationService.this.setPaying(true);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }

        public void reqPaymentStatus() throws RemoteException {
            CommunicationService.this.onPayingStatus();
        }

        public int getConnectStatus() throws RemoteException {
            return CommunicationService.this.connectionStatus;
        }

        public boolean isPaying() throws RemoteException {
            return CommunicationService.this.isPaying;
        }

        public void changeSocketUrl() throws RemoteException {
            CommunicationService.this.changeSocketUrl();
        }
    };
    /* access modifiers changed from: private */
    public Socket communicationSocket;
    /* access modifiers changed from: private */
    public final Handler connectHandler = new Handler();
    /* access modifiers changed from: private */
    public int connectionStatus = 1;
    /* access modifiers changed from: private */
    public boolean isPaying = false;
    private final String[] socketListenerMethods = {"customerCheckParameter", "failCustomerPayRequestStatus", "successCustomerPayRequestStatus", "failCustomerCancelPayGroup", "successCustomerCancelPayGroup", "successCustomerCheckPayGroupStatus", "failCustomerCheckPayGroupStatus", "customerInvitePayGroup", "serverSendInviteStatus", SocketInterface.METHOD_INVALID_PIN, "serverNotifyPayResult", "cashierCheckCustomerStatus", "failCustomerCustomerExtendAuthExpire", "successCustomerExtendAuthExpire", "cashierStartPayment", "cashierStartInputPrice", "cashierConfirmPayment"};
    private URI socketUrl;
    private boolean userDisconnect = false;

    public void setPaying(boolean isPaying2) {
        this.isPaying = isPaying2;
        onPayingStatus();
    }

    public boolean isPaying() {
        return this.isPaying;
    }

    public void onPayingStatus() {
        this.connectHandler.post(new Runnable() {
            public void run() {
                int callbackCnt = CommunicationService.this.callbackList.beginBroadcast();
                for (int i = 0; i < callbackCnt; i++) {
                    try {
                        ((ICommunicationServiceCallback) CommunicationService.this.callbackList.getBroadcastItem(i)).onChangePaymentStatus(CommunicationService.this.isPaying);
                    } catch (RemoteException e) {
                    }
                }
                CommunicationService.this.callbackList.finishBroadcast();
            }
        });
    }

    public void onCreate() {
        super.onCreate();
        this.callbackList = new RemoteCallbackList<>();
        this.socketUrl = URI.create(AppSettingManager.getInstance().getSocketUrl());
        setSocketConnection();
    }

    public void onDestroy() {
        super.onDestroy();
        disConnectSocket();
    }

    /* access modifiers changed from: private */
    public void changeSocketUrl() {
        this.socketUrl = URI.create(AppSettingManager.getInstance().getSocketUrl());
        setSocketConnection();
    }

    private void setSocketConnection() {
        String[] strArr;
        boolean isReconnect = false;
        Options opts = new Options();
        opts.forceNew = true;
        opts.reconnection = false;
        opts.query = "type=customer&auth_token=" + SessionManager.getInstance().getAuthToken();
        if (this.communicationSocket != null) {
            this.communicationSocket.off();
            this.communicationSocket.disconnect();
            this.communicationSocket = null;
            isReconnect = true;
        }
        this.communicationSocket = IO.socket(this.socketUrl, opts);
        this.communicationSocket.on(Socket.EVENT_CONNECT, new Listener() {
            public void call(Object... args) {
                CommunicationService.this.onChangeStatus(2);
            }
        });
        this.communicationSocket.on("reconnect", new Listener() {
            public void call(Object... args) {
                CommunicationService.this.onChangeStatus(2);
            }
        });
        this.communicationSocket.on(Socket.EVENT_DISCONNECT, new Listener() {
            public void call(Object... args) {
                CommunicationService.this.onChangeStatus(3);
            }
        });
        this.communicationSocket.on("reconnect_error", new Listener() {
            public void call(Object... args) {
                CommunicationService.this.onChangeStatus(3);
            }
        });
        this.communicationSocket.on("connect_error", new Listener() {
            public void call(Object... args) {
                CommunicationService.this.onChangeStatus(3);
            }
        });
        for (final String method : this.socketListenerMethods) {
            this.communicationSocket.on(method, new Listener() {
                public void call(Object... args) {
                    final JSONObject obj = args[0];
                    if (obj != null) {
                    }
                    if (!method.equals("successCustomerPayRequestStatus") && !method.equals("cashierCheckCustomerStatus") && !method.equals("serverNotifyPayResult") && !method.equals("failCustomerCustomerExtendAuthExpire") && !method.equals("successCustomerExtendAuthExpire")) {
                        CommunicationService.this.setPaying(false);
                    }
                    CommunicationService.this.connectHandler.post(new Runnable() {
                        public void run() {
                            int callbackCnt = CommunicationService.this.callbackList.beginBroadcast();
                            for (int i = 0; i < callbackCnt; i++) {
                                try {
                                    ((ICommunicationServiceCallback) CommunicationService.this.callbackList.getBroadcastItem(i)).onReceiveMessage(method, obj == null ? "" : obj.toString());
                                } catch (RemoteException e) {
                                }
                            }
                            CommunicationService.this.callbackList.finishBroadcast();
                        }
                    });
                }
            });
        }
        if (isReconnect) {
            connectSocket();
        }
    }

    /* access modifiers changed from: private */
    public void onChangeStatus(final int status) {
        this.connectionStatus = status;
        if (status == 3 && !this.userDisconnect) {
            retryConnect();
        }
        this.connectHandler.post(new Runnable() {
            public void run() {
                int callbackCnt = CommunicationService.this.callbackList.beginBroadcast();
                for (int i = 0; i < callbackCnt; i++) {
                    try {
                        ((ICommunicationServiceCallback) CommunicationService.this.callbackList.getBroadcastItem(i)).onChangeStatus(status);
                    } catch (RemoteException e) {
                    }
                }
                CommunicationService.this.callbackList.finishBroadcast();
            }
        });
    }

    /* access modifiers changed from: private */
    public void connectSocket() {
        this.userDisconnect = false;
        if (!this.communicationSocket.connected()) {
            this.communicationSocket.connect();
        }
    }

    private void disConnectSocket() {
        this.userDisconnect = true;
        if (this.communicationSocket.connected()) {
            this.communicationSocket.disconnect();
        }
    }

    private void retryConnect() {
        this.connectHandler.postDelayed(new Runnable() {
            public void run() {
                CommunicationService.this.connectSocket();
            }
        }, 1000);
    }

    @Nullable
    public IBinder onBind(Intent intent) {
        connectSocket();
        return this.communicationServiceBinder;
    }

    public int onStartCommand(Intent intent, int flags, int startId) {
        connectSocket();
        return 2;
    }
}