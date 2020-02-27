package com.nuvent.shareat;

import android.os.Binder;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;

public interface ICommunicationServiceCallback extends IInterface {

    public static abstract class Stub extends Binder implements ICommunicationServiceCallback {
        private static final String DESCRIPTOR = "com.nuvent.shareat.ICommunicationServiceCallback";
        static final int TRANSACTION_onChangePaymentStatus = 3;
        static final int TRANSACTION_onChangeStatus = 1;
        static final int TRANSACTION_onReceiveMessage = 2;

        private static class Proxy implements ICommunicationServiceCallback {
            private IBinder mRemote;

            Proxy(IBinder remote) {
                this.mRemote = remote;
            }

            public IBinder asBinder() {
                return this.mRemote;
            }

            public String getInterfaceDescriptor() {
                return Stub.DESCRIPTOR;
            }

            public void onChangeStatus(int status) throws RemoteException {
                Parcel _data = Parcel.obtain();
                try {
                    _data.writeInterfaceToken(Stub.DESCRIPTOR);
                    _data.writeInt(status);
                    this.mRemote.transact(1, _data, null, 1);
                } finally {
                    _data.recycle();
                }
            }

            public void onReceiveMessage(String method, String jsonValue) throws RemoteException {
                Parcel _data = Parcel.obtain();
                try {
                    _data.writeInterfaceToken(Stub.DESCRIPTOR);
                    _data.writeString(method);
                    _data.writeString(jsonValue);
                    this.mRemote.transact(2, _data, null, 1);
                } finally {
                    _data.recycle();
                }
            }

            public void onChangePaymentStatus(boolean paying) throws RemoteException {
                int i = 1;
                Parcel _data = Parcel.obtain();
                try {
                    _data.writeInterfaceToken(Stub.DESCRIPTOR);
                    if (!paying) {
                        i = 0;
                    }
                    _data.writeInt(i);
                    this.mRemote.transact(3, _data, null, 1);
                } finally {
                    _data.recycle();
                }
            }
        }

        public Stub() {
            attachInterface(this, DESCRIPTOR);
        }

        public static ICommunicationServiceCallback asInterface(IBinder obj) {
            if (obj == null) {
                return null;
            }
            IInterface iin = obj.queryLocalInterface(DESCRIPTOR);
            if (iin == null || !(iin instanceof ICommunicationServiceCallback)) {
                return new Proxy(obj);
            }
            return (ICommunicationServiceCallback) iin;
        }

        public IBinder asBinder() {
            return this;
        }

        public boolean onTransact(int code, Parcel data, Parcel reply, int flags) throws RemoteException {
            switch (code) {
                case 1:
                    data.enforceInterface(DESCRIPTOR);
                    onChangeStatus(data.readInt());
                    return true;
                case 2:
                    data.enforceInterface(DESCRIPTOR);
                    onReceiveMessage(data.readString(), data.readString());
                    return true;
                case 3:
                    data.enforceInterface(DESCRIPTOR);
                    onChangePaymentStatus(data.readInt() != 0);
                    return true;
                case 1598968902:
                    reply.writeString(DESCRIPTOR);
                    return true;
                default:
                    return super.onTransact(code, data, reply, flags);
            }
        }
    }

    void onChangePaymentStatus(boolean z) throws RemoteException;

    void onChangeStatus(int i) throws RemoteException;

    void onReceiveMessage(String str, String str2) throws RemoteException;
}