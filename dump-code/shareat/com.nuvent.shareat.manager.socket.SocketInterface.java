package com.nuvent.shareat.manager.socket;

import android.app.Activity;
import android.text.TextUtils;
import com.nuvent.shareat.R;
import com.nuvent.shareat.ShareatApp;
import com.nuvent.shareat.event.BarcodePayingEvent;
import com.nuvent.shareat.event.BarcodeRefreshEvent;
import com.nuvent.shareat.event.PayingEvent;
import com.nuvent.shareat.event.SocketReceiveEvent;
import com.nuvent.shareat.manager.socket.ComsSocketManager.SocketEventListener;
import com.nuvent.shareat.model.payment.PayResultModel;
import com.nuvent.shareat.util.GAEvent;
import de.greenrobot.event.EventBus;
import java.util.HashMap;
import java.util.Map;
import org.json.JSONException;
import org.json.JSONObject;

public class SocketInterface {
    public static final String METHOD_CREATE_PAY_GROUP = "customerCreatePayGroup";
    public static final String METHOD_CUSTOMER_CANCEL_PAY_GROUP = "customerCancelPayGroup";
    public static final String METHOD_CUSTOMER_CHECK_PAY_GROUP_STATUS = "customerCheckPayGroupStatus";
    public static final String METHOD_CUSTOMER_EXTEND_AUTH_EXPIRE = "customerExtendAuthExpire";
    public static final String METHOD_CUSTOMER_PAY_REQUEST_STATUS = "customerPayRequestStatusV12";
    public static final String METHOD_CUSTOMER_RESPONSE_CHECK_CUSTOMER_STATUS = "customerResponseCheckCustomerStatus";
    public static final String METHOD_CUSTOMER_SEND_INVITE_STATUS = "customerSendInviteStatus";
    public static final String METHOD_INVALID_PIN = "customerInvalidPin";
    public static final String METHOD_REFRESH_SOCKET = "refreshSocket";
    public static final int PAYING_BARCODE_FAIL = 23;
    public static final int PAYING_CANCLE = 21;
    public static final int PAYING_CANCLE_ERROR = 22;
    public static final int PAYING_ERROR = 19;
    public static final int PAYING_REQUEST = 17;
    public static final int PAYING_REQUEST_BARCODE = 24;
    public static final int PAYING_RESPONSE = 18;
    public static final int PAYING_WRONG_PW = 20;
    private Activity mActivity;
    private ComsSocketManager mComsSocketManager;
    private String mGroupCode;
    private String mPartnerSno;
    private Map<String, Handler> mReceiveHandlerMap;
    /* access modifiers changed from: private */
    public long sTime;
    private SocketEventListener socketEventListener = new SocketEventListener() {
        public void onChangeStatus(int status) {
            if (status != 1) {
                if (status == 2) {
                    SocketInterface.this.sTime = System.currentTimeMillis();
                }
            }
        }

        public void onConnect() {
        }

        public void onDisconnect() {
        }

        public void onMessage(String method, JSONObject parameter) {
            SocketInterface.this.onReceiveMessage(method, parameter);
        }

        public void onChangePayingStatus(boolean paying) {
            EventBus.getDefault().post(new PayingEvent(paying));
        }
    };

    public interface Handler {
        void handlerData(String str, JSONObject jSONObject);
    }

    public SocketInterface(Activity activity) {
        this.mActivity = activity;
        this.mReceiveHandlerMap = new HashMap();
        this.mComsSocketManager = new ComsSocketManager(activity);
        this.mComsSocketManager.setSocketEventListener(this.socketEventListener);
        registerHandler();
        init();
    }

    public void registServiceBind() {
        this.mComsSocketManager.registServiceBind();
    }

    public void unregistServiceBind() {
        this.mComsSocketManager.unRegistServiceBind();
    }

    public void init() {
        if (this.mGroupCode != null && !this.mGroupCode.equals("")) {
            this.mGroupCode = null;
            this.mPartnerSno = null;
        }
    }

    public boolean isPaying() {
        return this.mComsSocketManager.isPaying();
    }

    /* access modifiers changed from: private */
    public void onReceiveMessage(String method, JSONObject parameter) {
        Handler handler = this.mReceiveHandlerMap.get(method);
        if (handler != null) {
            handler.handlerData(method, parameter);
        }
    }

    public void onSendMessage(String methodStr, Map<String, String> datas) {
        try {
            JSONObject requestData = new JSONObject();
            if (datas != null) {
                if (datas.get("partner_sno") != null) {
                    this.mPartnerSno = datas.get("partner_sno");
                }
                if (METHOD_CUSTOMER_EXTEND_AUTH_EXPIRE.equals(methodStr)) {
                    datas.put("tmp_group_id", this.mGroupCode);
                }
                for (String key : datas.keySet()) {
                    requestData.put(key, datas.get(key));
                }
            }
            this.sTime = System.currentTimeMillis();
            this.mComsSocketManager.sendMessage(methodStr, requestData);
        } catch (JSONException e) {
            e.printStackTrace();
        }
    }

    public void onCancelPaying() {
        if (this.mPartnerSno != null && this.mGroupCode != null && !this.mPartnerSno.isEmpty() && !this.mGroupCode.isEmpty()) {
            Map<String, String> dataMap = new HashMap<>();
            dataMap.put("partner_sno", this.mPartnerSno);
            dataMap.put("tmp_group_id", this.mGroupCode);
            onSendMessage(METHOD_CUSTOMER_CANCEL_PAY_GROUP, dataMap);
            init();
        }
    }

    public void setSocketUrl(String url) {
        this.mComsSocketManager.setSocketUrl(url);
    }

    /* access modifiers changed from: private */
    public void customerCheckParameter(String method, JSONObject object) {
        setGAEvent("customerCheckParameter", R.string.app_socket_customer_check_parameter, System.currentTimeMillis() - this.sTime);
    }

    /* access modifiers changed from: private */
    public void failCustomerPayRequestStatus(String method, JSONObject object) {
        setGAEvent("failCustomerPayRequestStatus", R.string.app_socket_fail_customer_pay_request_status, System.currentTimeMillis() - this.sTime);
        EventBus.getDefault().post(new SocketReceiveEvent(22, ShareatApp.getInstance().getResources().getString(R.string.paying_cancle_endalbe_msg_error)));
    }

    /* access modifiers changed from: private */
    public void successCustomerPayRequestStatus(String method, JSONObject object) {
        setGAEvent("successCustomerPayRequestStatus", R.string.app_socket_success_customer_pay_request_status, System.currentTimeMillis() - this.sTime);
        try {
            this.mGroupCode = object.getString("tmp_group_id");
            if (object.has("pin_no")) {
                EventBus.getDefault().post(new BarcodePayingEvent(object.getString("pin_no"), object.getString("expire_date"), object.has("brand_img_url") ? object.getString("brand_img_url") : ""));
            }
        } catch (JSONException e) {
            e.printStackTrace();
        }
    }

    /* access modifiers changed from: private */
    public void failCustomerCancelPayGroup(String method, JSONObject object) {
        setGAEvent("failCustomerCancelPayGroup", R.string.app_socket_fail_customer_cancel_pay_group, System.currentTimeMillis() - this.sTime);
        if (object != null) {
            String result = "";
            try {
                result = object.getString("result");
            } catch (JSONException e) {
                e.printStackTrace();
            }
            EventBus.getDefault().post(new SocketReceiveEvent(22, ShareatApp.getInstance().getResources().getString((result == null || !result.equals("L")) ? R.string.paying_cancle_endalbe_msg_error : R.string.paying_cancle_endalbe_msg)));
        }
    }

    /* access modifiers changed from: private */
    public void successCustomerCancelPayGroup(String method, JSONObject object) {
        setGAEvent("successCustomerCancelPayGroup", R.string.app_socket_success_customer_cancel_pay_group, System.currentTimeMillis() - this.sTime);
        EventBus.getDefault().post(new SocketReceiveEvent(21, ShareatApp.getInstance().getResources().getString(R.string.paying_cancle_msg)));
        init();
    }

    /* access modifiers changed from: private */
    public void successCustomerCheckPayGroupStatus(String method, JSONObject object) {
        setGAEvent("successCustomerCheckPayGroupStatus", R.string.app_socket_success_customer_check_pay_group_status, System.currentTimeMillis() - this.sTime);
        PayResultModel payResultParam = (PayResultModel) new PayResultModel().fromJson(object.toString());
        payResultParam.UriDecode();
        if (payResultParam.group_pay_status != 20) {
            EventBus.getDefault().post(new SocketReceiveEvent(18, object == null ? "" : object.toString()));
        }
    }

    /* access modifiers changed from: private */
    public void failCustomerCheckPayGroupStatus(String method, JSONObject object) {
        init();
    }

    /* access modifiers changed from: private */
    public void customerInvitePayGroup(String method, JSONObject object) {
    }

    /* access modifiers changed from: private */
    public void serverSendInviteStatus(String method, JSONObject object) {
    }

    /* access modifiers changed from: private */
    public void customerInvalidPin(String method, JSONObject object) {
        setGAEvent(METHOD_INVALID_PIN, R.string.app_socket_customer_invalid_pin, System.currentTimeMillis() - this.sTime);
        EventBus.getDefault().post(new SocketReceiveEvent(20, ShareatApp.getInstance().getResources().getString(R.string.paying_pw_wrong_msg)));
    }

    /* access modifiers changed from: private */
    public void serverNotifyPayResult(String method, JSONObject object) {
        setGAEvent("serverNotifyPayResult", R.string.app_socket_server_notify_pay_result, System.currentTimeMillis() - this.sTime);
        if (isPaying()) {
            EventBus.getDefault().post(new SocketReceiveEvent(18, object == null ? "" : object.toString()));
            this.mGroupCode = null;
            this.mComsSocketManager.sendMessage((String) "endPay", (String) "");
        }
    }

    /* access modifiers changed from: private */
    public void failCustomerCustomerExtendAuthExpire(String method, JSONObject object) {
        setGAEvent("failCustomerCustomerExtendAuthExpire", R.string.app_socket_server_notify_pay_result, System.currentTimeMillis() - this.sTime);
        if (isPaying()) {
            EventBus.getDefault().post(new BarcodeRefreshEvent("failCustomerCustomerExtendAuthExpire", ""));
        }
    }

    /* access modifiers changed from: private */
    public void successCustomerExtendAuthExpire(String method, JSONObject object) {
        setGAEvent("successCustomerExtendAuthExpire", R.string.app_socket_server_notify_pay_result, System.currentTimeMillis() - this.sTime);
        if (isPaying()) {
            try {
                EventBus.getDefault().post(new BarcodeRefreshEvent("successCustomerExtendAuthExpire", object.getString("expire_date")));
            } catch (JSONException e) {
                e.printStackTrace();
            }
        }
    }

    /* access modifiers changed from: private */
    public void cashierCheckCustomerStatus(String method, JSONObject object) {
        setGAEvent("cashierCheckCustomerStatus", R.string.app_socket_cashier_check_customer_status, System.currentTimeMillis() - this.sTime);
        Map<String, String> dataMap = new HashMap<>();
        if (!TextUtils.isEmpty(this.mGroupCode)) {
            String status = isPaying() ? "20" : "60";
            dataMap.put("tmp_group_id", this.mGroupCode);
            dataMap.put("status", status);
        } else {
            dataMap.put("status", "60");
        }
        onSendMessage(METHOD_CUSTOMER_RESPONSE_CHECK_CUSTOMER_STATUS, dataMap);
    }

    /* access modifiers changed from: private */
    public void cashierStartPayment(String method, JSONObject object) {
    }

    /* access modifiers changed from: private */
    public void cashierStartInputPrice(String method, JSONObject object) {
    }

    /* access modifiers changed from: private */
    public void cashierConfirmPayment(String method, JSONObject object) {
    }

    private void registerHandler() {
        this.mReceiveHandlerMap.put("customerCheckParameter", new Handler() {
            public void handlerData(String method, JSONObject parameter) {
                SocketInterface.this.customerCheckParameter(method, parameter);
            }
        });
        this.mReceiveHandlerMap.put("failCustomerPayRequestStatus", new Handler() {
            public void handlerData(String method, JSONObject parameter) {
                SocketInterface.this.failCustomerPayRequestStatus(method, parameter);
            }
        });
        this.mReceiveHandlerMap.put("successCustomerPayRequestStatus", new Handler() {
            public void handlerData(String method, JSONObject parameter) {
                SocketInterface.this.successCustomerPayRequestStatus(method, parameter);
            }
        });
        this.mReceiveHandlerMap.put("failCustomerCancelPayGroup", new Handler() {
            public void handlerData(String method, JSONObject parameter) {
                SocketInterface.this.failCustomerCancelPayGroup(method, parameter);
            }
        });
        this.mReceiveHandlerMap.put("successCustomerCancelPayGroup", new Handler() {
            public void handlerData(String method, JSONObject parameter) {
                SocketInterface.this.successCustomerCancelPayGroup(method, parameter);
            }
        });
        this.mReceiveHandlerMap.put("successCustomerCheckPayGroupStatus", new Handler() {
            public void handlerData(String method, JSONObject parameter) {
                SocketInterface.this.successCustomerCheckPayGroupStatus(method, parameter);
            }
        });
        this.mReceiveHandlerMap.put("failCustomerCheckPayGroupStatus", new Handler() {
            public void handlerData(String method, JSONObject parameter) {
                SocketInterface.this.failCustomerCheckPayGroupStatus(method, parameter);
            }
        });
        this.mReceiveHandlerMap.put("customerInvitePayGroup", new Handler() {
            public void handlerData(String method, JSONObject parameter) {
                SocketInterface.this.customerInvitePayGroup(method, parameter);
            }
        });
        this.mReceiveHandlerMap.put("serverSendInviteStatus", new Handler() {
            public void handlerData(String method, JSONObject parameter) {
                SocketInterface.this.serverSendInviteStatus(method, parameter);
            }
        });
        this.mReceiveHandlerMap.put(METHOD_INVALID_PIN, new Handler() {
            public void handlerData(String method, JSONObject parameter) {
                SocketInterface.this.customerInvalidPin(method, parameter);
            }
        });
        this.mReceiveHandlerMap.put("serverNotifyPayResult", new Handler() {
            public void handlerData(String method, JSONObject parameter) {
                SocketInterface.this.serverNotifyPayResult(method, parameter);
            }
        });
        this.mReceiveHandlerMap.put("cashierCheckCustomerStatus", new Handler() {
            public void handlerData(String method, JSONObject parameter) {
                SocketInterface.this.cashierCheckCustomerStatus(method, parameter);
            }
        });
        this.mReceiveHandlerMap.put("failCustomerCustomerExtendAuthExpire", new Handler() {
            public void handlerData(String method, JSONObject parameter) {
                SocketInterface.this.failCustomerCustomerExtendAuthExpire(method, parameter);
            }
        });
        this.mReceiveHandlerMap.put("successCustomerExtendAuthExpire", new Handler() {
            public void handlerData(String method, JSONObject parameter) {
                SocketInterface.this.successCustomerExtendAuthExpire(method, parameter);
            }
        });
        this.mReceiveHandlerMap.put("cashierStartPayment", new Handler() {
            public void handlerData(String method, JSONObject parameter) {
                SocketInterface.this.cashierStartPayment(method, parameter);
            }
        });
        this.mReceiveHandlerMap.put("cashierStartInputPrice", new Handler() {
            public void handlerData(String method, JSONObject parameter) {
                SocketInterface.this.cashierStartInputPrice(method, parameter);
            }
        });
        this.mReceiveHandlerMap.put("cashierConfirmPayment", new Handler() {
            public void handlerData(String method, JSONObject parameter) {
                SocketInterface.this.cashierConfirmPayment(method, parameter);
            }
        });
    }

    private void setGAEvent(String action, int actionId, long eTime) {
        GAEvent.onUserTimings(this.mActivity, R.string.app_socket_time, eTime, actionId, R.string.app_socket_time);
    }
}