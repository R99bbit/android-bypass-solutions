package com.igaworks.commerce.net;

import android.content.Context;
import android.util.Log;
import com.igaworks.commerce.core.CommerceRequestParameter;
import com.igaworks.commerce.db.CommerceEventDAO;
import com.igaworks.commerce.db.CommerceEventV2DAO;
import com.igaworks.commerce.db.DemographicDAO;
import com.igaworks.commerce.db.PurchaseRetryDAO;
import com.igaworks.commerce.model.CommerceV2EventItem;
import com.igaworks.commerce.model.PurchaseItem;
import com.igaworks.core.AESGetTrackParam;
import com.igaworks.core.AdvertisingIdClient.ADIDCallbackListener;
import com.igaworks.core.AdvertisingIdClient.AdInfo;
import com.igaworks.core.DeviceIDManger;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;
import com.igaworks.core.RequestParameter;
import com.igaworks.impl.InternalAction;
import com.igaworks.interfaces.HttpCallbackListener;
import com.igaworks.net.CommonHttpManager;
import com.igaworks.net.HttpManager;
import com.igaworks.net.JsonHttpsUrlConnectionThread;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class CommerceHttpManager extends CommonHttpManager {
    public static final String ERR_MSG = "errMsg";
    public static String cmc_domain = HttpManager.DEEPLINK_DOMAIN_LIVE;
    public String EVENT_REQUEST_URL_FOR_Commerce = (cmc_domain + "tracking/customEvents");
    public String EVENT_REQUEST_URL_FOR_Commerce_V2 = (cmc_domain + "event");
    public String PURCHASE_REQUEST_URL_FOR_Commerce = (cmc_domain + "tracking/purchases");

    public void purchaseForCommerce(final RequestParameter parameter, final Context context, final ArrayList<PurchaseItem> items) {
        InternalAction.NETWORK_EXECUTOR.execute(new Runnable() {
            public void run() {
                try {
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "purchaseForCommerce", 3);
                    DeviceIDManger instance = DeviceIDManger.getInstance(context);
                    Context context = context;
                    final ArrayList arrayList = items;
                    final RequestParameter requestParameter = parameter;
                    final Context context2 = context;
                    instance.getAndroidADID(context, new ADIDCallbackListener() {
                        public void onResult(AdInfo adInfo) {
                            String url = CommerceHttpManager.this.PURCHASE_REQUEST_URL_FOR_Commerce;
                            JSONArray arr = new JSONArray();
                            Iterator it = arrayList.iterator();
                            while (it.hasNext()) {
                                PurchaseItem item = (PurchaseItem) it.next();
                                try {
                                    String[] categories = new String[5];
                                    String[] temp = item.getCategory() != null ? item.getCategory().split("\\.") : new String[0];
                                    for (int i = 0; i < temp.length; i++) {
                                        categories[i] = temp[i];
                                    }
                                    JSONObject obj = new JSONObject();
                                    String event_id = UUID.randomUUID().toString();
                                    obj.put("ak", requestParameter.getAppkey());
                                    obj.put("adid", adInfo.getId());
                                    obj.put("usn", DemographicDAO.getDemographic(context2, DemographicDAO.KEY_USN));
                                    obj.put("emailhash", DemographicDAO.getDemographic(context2, "email"));
                                    obj.put("orderId", item.getOrderID());
                                    obj.put("productId", item.getProductID());
                                    obj.put("price", item.getPrice());
                                    obj.put("currency", item.getCurrency());
                                    obj.put("category1", categories[0]);
                                    obj.put("category2", categories[1]);
                                    obj.put("category3", categories[2]);
                                    obj.put("category4", categories[3]);
                                    obj.put("category5", categories[4]);
                                    obj.put("quantity", item.getQuantity());
                                    obj.put("productName", item.getProductName());
                                    obj.put("event_id", event_id);
                                    obj.put("mtime", new Date().getTime());
                                    arr.put(obj);
                                } catch (JSONException e) {
                                    e.printStackTrace();
                                }
                            }
                            try {
                                Context context = context2;
                                String jSONArray = arr.toString();
                                final Context context2 = context2;
                                final ArrayList arrayList = arrayList;
                                WeakReference weakReference = new WeakReference(new JsonHttpsUrlConnectionThread(context, 1, url, jSONArray, new HttpCallbackListener() {
                                    public void callback(String result) {
                                        if (result != null) {
                                            try {
                                                if (!result.equals("")) {
                                                    IgawLogger.Logging(context2, IgawConstant.QA_TAG, "ADBrixTracer, commerce purchase response result : " + result, 3, false);
                                                    JSONObject jsonObject = new JSONObject(result);
                                                    if (!jsonObject.has("errMsg") || !jsonObject.isNull("errMsg")) {
                                                        CommerceHttpManager.this.restorePurchaseInfo(context2, arrayList);
                                                        return;
                                                    } else {
                                                        PurchaseRetryDAO.getDAO(context2).removePurchaseItem(arrayList, context2);
                                                        return;
                                                    }
                                                }
                                            } catch (Exception e) {
                                                e.printStackTrace();
                                                CommerceHttpManager.this.restorePurchaseInfo(context2, arrayList);
                                                IgawLogger.Logging(context2, IgawConstant.QA_TAG, e.getMessage(), 0);
                                                return;
                                            }
                                        }
                                        throw new Exception("responseResult null Error");
                                    }
                                }, false, false));
                                ((Thread) weakReference.get()).setDaemon(true);
                                ((Thread) weakReference.get()).start();
                            } catch (Exception e2) {
                                CommerceHttpManager.this.restorePurchaseInfo(context2, arrayList);
                                e2.printStackTrace();
                                IgawLogger.Logging(context2, IgawConstant.QA_TAG, e2.toString(), 0);
                            }
                        }
                    });
                } catch (Exception e) {
                    e.printStackTrace();
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, e.toString(), 0);
                    CommerceHttpManager.this.restorePurchaseInfo(context, items);
                }
            }
        });
    }

    public void eventForCommerceV2(RequestParameter parameter, final Context context, final ArrayList<CommerceV2EventItem> items) {
        InternalAction.NETWORK_EXECUTOR.execute(new Runnable() {
            public void run() {
                DeviceIDManger instance = DeviceIDManger.getInstance(context);
                Context context = context;
                final Context context2 = context;
                final ArrayList arrayList = items;
                instance.getAndroidADID(context, new ADIDCallbackListener() {
                    public void onResult(AdInfo adInfo) {
                        String adid = adInfo == null ? "" : adInfo.getId();
                        boolean optout = adInfo == null ? false : adInfo.isLimitAdTrackingEnabled();
                        try {
                            IgawLogger.Logging(context2, IgawConstant.QA_TAG, "eventForCommerceV2", 3);
                            String url = CommerceHttpManager.this.EVENT_REQUEST_URL_FOR_Commerce_V2;
                            String rootString = CommerceRequestParameter.getCommerceV2EventParameter(context2, adid, optout, arrayList, 1);
                            IgawLogger.Logging(context2, IgawConstant.QA_TAG, "customEventForCommerceV2" + rootString, 3);
                            try {
                                Context context = context2;
                                final Context context2 = context2;
                                final ArrayList arrayList = arrayList;
                                WeakReference<Thread> threadW = new WeakReference<>(new JsonHttpsUrlConnectionThread(context, 1, url, rootString, new HttpCallbackListener() {
                                    public void callback(String result) {
                                        if (result != null) {
                                            try {
                                                if (!result.equals("")) {
                                                    IgawLogger.Logging(context2, IgawConstant.QA_TAG, "ADBrixTracer, event for ommerceV2 response result : " + result, 3, false);
                                                    if (new JSONObject(result).getBoolean(HttpManager.RESULT)) {
                                                        CommerceEventV2DAO.getDAO(context2).removePurchaseItem(arrayList, context2);
                                                        return;
                                                    } else {
                                                        CommerceHttpManager.this.restoreCV2EventInfo(context2, arrayList);
                                                        return;
                                                    }
                                                }
                                            } catch (Exception e) {
                                                e.printStackTrace();
                                                CommerceHttpManager.this.restoreCV2EventInfo(context2, arrayList);
                                                IgawLogger.Logging(context2, IgawConstant.QA_TAG, e.getMessage(), 0);
                                                return;
                                            }
                                        }
                                        throw new Exception("responseResult null Error");
                                    }
                                }, false, false));
                                ((Thread) threadW.get()).setDaemon(true);
                                ((Thread) threadW.get()).start();
                            } catch (Exception e) {
                                CommerceHttpManager.this.restoreCV2EventInfo(context2, arrayList);
                                e.printStackTrace();
                                IgawLogger.Logging(context2, IgawConstant.QA_TAG, e.toString(), 0);
                            }
                        } catch (Exception e2) {
                            e2.printStackTrace();
                            IgawLogger.Logging(context2, IgawConstant.QA_TAG, e2.toString(), 0);
                            CommerceHttpManager.this.restoreCV2EventInfo(context2, arrayList);
                        }
                    }
                });
            }
        });
    }

    public void customEventForCommerce(RequestParameter parameter, final Context context, final List<String> items, final int ServerType) {
        InternalAction.NETWORK_EXECUTOR.execute(new Runnable() {
            public void run() {
                try {
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "customEventForCommerce", 3);
                    DeviceIDManger instance = DeviceIDManger.getInstance(context);
                    Context context = context;
                    final int i = ServerType;
                    final Context context2 = context;
                    final List list = items;
                    instance.getAndroidADID(context, new ADIDCallbackListener() {
                        public void onResult(AdInfo adInfo) {
                            String url = CommerceHttpManager.this.EVENT_REQUEST_URL_FOR_Commerce;
                            if (i == 1) {
                                url = CommerceHttpManager.this.EVENT_REQUEST_URL_FOR_Commerce_V2;
                            }
                            String adid = adInfo == null ? "" : adInfo.getId();
                            boolean optout = adInfo == null ? false : adInfo.isLimitAdTrackingEnabled();
                            String param = "";
                            try {
                                if (i == 0) {
                                    param = AESGetTrackParam.encrypt(CommerceRequestParameter.getCommerceEventParameter(context2, adid, optout, list, 0), "");
                                }
                                JSONObject root = new JSONObject();
                                root.put("j", param);
                                String rootString = "";
                                if (i == 0) {
                                    rootString = root.toString();
                                }
                                if (i == 1) {
                                    rootString = CommerceRequestParameter.getCommerceEventParameter(context2, adid, optout, list, 1);
                                    IgawLogger.Logging(context2, IgawConstant.QA_TAG, "customEventForCommerceV2" + rootString, 3);
                                }
                                Context context = context2;
                                final Context context2 = context2;
                                final int i = i;
                                final List list = list;
                                WeakReference<Thread> threadW = new WeakReference<>(new JsonHttpsUrlConnectionThread(context, 1, url, rootString, new HttpCallbackListener() {
                                    public void callback(String result) {
                                        if (result != null) {
                                            try {
                                                if (!result.equals("")) {
                                                    IgawLogger.Logging(context2, IgawConstant.QA_TAG, "ADBrixTracer, commerce event response result : " + result, 3, false);
                                                    JSONObject jsonObject = new JSONObject(result);
                                                    if (i == 0) {
                                                        if (!jsonObject.has("errMsg") || !jsonObject.isNull("errMsg")) {
                                                            CommerceHttpManager.this.restoreCEventInfo(context2, list);
                                                            return;
                                                        }
                                                        return;
                                                    } else if (i != 1) {
                                                        return;
                                                    } else {
                                                        if (jsonObject.getBoolean(HttpManager.RESULT)) {
                                                            IgawLogger.Logging(context2, IgawConstant.QA_TAG, "result arimasida True", 3);
                                                            return;
                                                        } else {
                                                            IgawLogger.Logging(context2, IgawConstant.QA_TAG, "result arimasida False", 3);
                                                            return;
                                                        }
                                                    }
                                                }
                                            } catch (Exception e) {
                                                e.printStackTrace();
                                                if (i == 0) {
                                                    CommerceHttpManager.this.restoreCEventInfo(context2, list);
                                                }
                                                IgawLogger.Logging(context2, IgawConstant.QA_TAG, e.getMessage(), 0);
                                                return;
                                            }
                                        }
                                        throw new Exception("responseResult null Error");
                                    }
                                }, false, false));
                                ((Thread) threadW.get()).setDaemon(true);
                                ((Thread) threadW.get()).start();
                            } catch (Exception e) {
                                if (i == 0) {
                                    CommerceHttpManager.this.restoreCEventInfo(context2, list);
                                }
                                e.printStackTrace();
                                IgawLogger.Logging(context2, IgawConstant.QA_TAG, e.toString(), 0);
                            }
                        }
                    });
                } catch (Exception e) {
                    e.printStackTrace();
                    if (ServerType == 0) {
                        CommerceHttpManager.this.restoreCEventInfo(context, items);
                    }
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, e.toString(), 0);
                }
            }
        });
    }

    public void restorePurchaseInfo(Context context, List<PurchaseItem> items) {
        PurchaseRetryDAO dao = PurchaseRetryDAO.getDAO(context);
        for (PurchaseItem item : items) {
            if (item.getRetryCnt() > 5) {
                dao.removeRetryCount(item.getKey());
            } else {
                dao.updateOrInsertConversionForRetry(item.getKey(), item.getOrderID(), item.getProductID(), item.getProductName(), item.getPrice(), item.getQuantity(), item.getCurrency(), item.getCategory(), item.getCreatedAt());
            }
        }
    }

    /* access modifiers changed from: private */
    public void restoreCEventInfo(Context context, List<String> items) {
        CommerceEventDAO.addEvents(context, items);
    }

    /* access modifiers changed from: private */
    public void restoreCV2EventInfo(Context context, List<CommerceV2EventItem> items) {
        Log.i("hoiil", "\uc800\uc7a5\ud588\ub2e4" + items.toString());
        CommerceEventV2DAO dao = CommerceEventV2DAO.getDAO(context);
        for (CommerceV2EventItem item : items) {
            if (item.getRetryCnt() > 5) {
                dao.removeRetryCount(item.getKey());
            } else {
                dao.updateOrInsertConversion(item.getKey(), item.getJson());
            }
        }
    }
}