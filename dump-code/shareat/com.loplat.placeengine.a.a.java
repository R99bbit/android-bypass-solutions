package com.loplat.placeengine.a;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import com.facebook.internal.NativeProtocol;
import com.kakao.kakaolink.internal.KakaoTalkLinkProtocol;
import com.loplat.placeengine.Plengi;
import com.loplat.placeengine.PlengiListener;
import com.loplat.placeengine.PlengiResponse;
import com.loplat.placeengine.PlengiResponse.Person;
import com.loplat.placeengine.PlengiResponse.Place;
import com.loplat.placeengine.PlengiResponse.Uuidp;
import com.loplat.placeengine.b;
import com.loplat.placeengine.c;
import com.loplat.placeengine.utils.LoplatLogger;
import io.fabric.sdk.android.services.network.HttpRequest;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.util.ArrayList;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* compiled from: CloudEndpoint */
public class a {
    Context a = null;
    String b = "";

    public a(Context context) {
        this.a = context;
    }

    public void a(final String destination, final String parameters) {
        new Thread(new Runnable() {
            public void run() {
                a.this.b(destination, parameters);
            }
        }).start();
    }

    public void b(String destination, String parameters) {
        LoplatLogger.writeLog("isNetworkAvailable: " + a(this.a));
        try {
            URL url = new URL("https://banded-totality-629.appspot.com/" + destination);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setDoOutput(true);
            connection.setDoInput(true);
            connection.setConnectTimeout(30000);
            connection.setReadTimeout(30000);
            connection.setRequestProperty("Accept", "application/json");
            connection.setRequestProperty("Content-type", "application/json");
            connection.setRequestMethod(HttpRequest.METHOD_POST);
            OutputStreamWriter outputStreamWriter = new OutputStreamWriter(connection.getOutputStream());
            outputStreamWriter.write(parameters);
            outputStreamWriter.flush();
            outputStreamWriter.close();
            InputStreamReader inputStreamReader = new InputStreamReader(connection.getInputStream());
            BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
            StringBuilder sb = new StringBuilder();
            while (true) {
                String line = bufferedReader.readLine();
                if (line == null) {
                    break;
                }
                sb.append(line + "\n");
            }
            String response = sb.toString();
            LoplatLogger.writeLog("Cloud Response: " + response);
            try {
                JSONObject jSONObject = new JSONObject(response);
                String status = jSONObject.getString("status");
                String type = jSONObject.getString(KakaoTalkLinkProtocol.ACTION_TYPE);
                if (!status.contains("success")) {
                    String reason = jSONObject.getString("reason");
                    LoplatLogger.writeLog("Cloud Error: " + reason);
                    Plengi plengi = Plengi.getInstance(null);
                    if (plengi != null) {
                        PlengiResponse plengiResponse = new PlengiResponse();
                        if (type.equals("searchplace")) {
                            plengiResponse.type = 1;
                            plengiResponse.result = 2;
                            plengiResponse.errorReason = reason;
                            PlengiListener listener = plengi.getListener();
                            if (listener != null) {
                                listener.listen(plengiResponse);
                            }
                        } else if (type.equals("searchplace_internal")) {
                            if (com.loplat.placeengine.c.a.p(this.a) == 0) {
                                if (b.h(this.a) == 4) {
                                    b.a(this.a, 0);
                                    b.a(this.a);
                                }
                            } else if (com.loplat.placeengine.c.a.p(this.a) == 1) {
                                LoplatLogger.writeLog("TRACKER: Cloud Error " + c.c(this.a));
                                if (c.c(this.a) == 2) {
                                    plengiResponse.type = 3;
                                    plengiResponse.place = null;
                                    PlengiListener listener2 = plengi.getListener();
                                    if (listener2 != null) {
                                        listener2.listen(plengiResponse);
                                    }
                                }
                                c.a(this.a, (Place) null);
                            }
                        } else if (type.contains("colocate")) {
                            plengiResponse.type = 5;
                            plengiResponse.result = 2;
                            plengiResponse.errorReason = reason;
                            PlengiListener listener3 = plengi.getListener();
                            if (listener3 != null) {
                                listener3.listen(plengiResponse);
                            }
                        }
                    } else {
                        LoplatLogger.writeLog("Get Engine Client Error!!!!!!");
                    }
                } else if (type.equals("searchplace")) {
                    JSONObject placeObj = jSONObject.getJSONObject("place");
                    String name = placeObj.getString("name");
                    String tags = placeObj.getString("tags");
                    String category = placeObj.getString("category");
                    float accuracy = (float) placeObj.getDouble("accuracy");
                    float threshold = (float) placeObj.getDouble("threshold");
                    double lat = placeObj.getDouble("lat");
                    double lng = placeObj.getDouble("lng");
                    int floor = placeObj.getInt("floor");
                    long loplatid = 0;
                    if (!placeObj.isNull("loplat_id")) {
                        loplatid = placeObj.getLong("loplat_id");
                    }
                    String clientCode = null;
                    if (placeObj.isNull("client_code")) {
                        LoplatLogger.printLog("code is null");
                    } else {
                        clientCode = placeObj.getString("client_code");
                        LoplatLogger.printLog("code is " + clientCode);
                        if (clientCode.equals("")) {
                            clientCode = null;
                        }
                    }
                    PlengiResponse plengiResponse2 = new PlengiResponse();
                    plengiResponse2.type = 1;
                    plengiResponse2.place = new Place();
                    plengiResponse2.place.name = name;
                    plengiResponse2.place.tags = tags;
                    plengiResponse2.place.category = category;
                    plengiResponse2.place.lat = lat;
                    plengiResponse2.place.lng = lng;
                    plengiResponse2.place.floor = floor;
                    plengiResponse2.place.accuracy = accuracy;
                    plengiResponse2.place.threshold = threshold;
                    plengiResponse2.place.lat_est = placeObj.getDouble("lat_est");
                    plengiResponse2.place.lng_est = placeObj.getDouble("lng_est");
                    plengiResponse2.place.client_code = clientCode;
                    plengiResponse2.place.loplatid = loplatid;
                    if (com.loplat.placeengine.c.a.p(this.a) == 0) {
                        if (accuracy > threshold && accuracy < 1.0f) {
                            b.a(this.a, name, tags, category, floor, clientCode, loplatid);
                            LoplatLogger.writeLog("Update placename: " + name);
                        }
                        b.a(this.a, lat, lng, accuracy, threshold);
                    } else if (com.loplat.placeengine.c.a.p(this.a) == 1 && accuracy > threshold) {
                        LoplatLogger.writeLog("Update placename: " + name);
                        c.a(this.a, plengiResponse2.place);
                    }
                    Plengi plengi2 = Plengi.getInstance(null);
                    if (plengi2 != null) {
                        PlengiListener listener4 = plengi2.getListener();
                        if (listener4 != null) {
                            listener4.listen(plengiResponse2);
                        }
                    } else {
                        LoplatLogger.writeLog("Get Engine Client Error!!!!!!");
                    }
                } else if (type.equals("searchplace_internal")) {
                    JSONObject placeObj2 = jSONObject.getJSONObject("place");
                    String name2 = placeObj2.getString("name");
                    String tags2 = placeObj2.getString("tags");
                    String category2 = placeObj2.getString("category");
                    float accuracy2 = (float) placeObj2.getDouble("accuracy");
                    float threshold2 = (float) placeObj2.getDouble("threshold");
                    double lat2 = placeObj2.getDouble("lat");
                    double lng2 = placeObj2.getDouble("lng");
                    int floor2 = placeObj2.getInt("floor");
                    long loplatid2 = 0;
                    if (!placeObj2.isNull("loplat_id")) {
                        loplatid2 = placeObj2.getLong("loplat_id");
                    }
                    String clientCode2 = null;
                    if (!placeObj2.isNull("client_code")) {
                        clientCode2 = placeObj2.getString("client_code");
                        if (clientCode2.equals("")) {
                            clientCode2 = null;
                        }
                    }
                    LoplatLogger.writeLog("searchplace_internal --------------:" + name2);
                    String clientCodePrev = com.loplat.placeengine.c.a.l(this.a);
                    LoplatLogger.writeLog("client_code: " + clientCode2 + ", previous: " + clientCodePrev);
                    if (com.loplat.placeengine.c.a.p(this.a) == 0) {
                        PlengiResponse plengiResponse3 = new PlengiResponse();
                        plengiResponse3.type = 2;
                        plengiResponse3.place = new Place();
                        plengiResponse3.place.name = name2;
                        plengiResponse3.place.tags = tags2;
                        plengiResponse3.place.category = category2;
                        plengiResponse3.place.lat = lat2;
                        plengiResponse3.place.lng = lng2;
                        plengiResponse3.place.floor = floor2;
                        plengiResponse3.place.accuracy = accuracy2;
                        plengiResponse3.place.threshold = threshold2;
                        plengiResponse3.place.lat_est = placeObj2.getDouble("lat_est");
                        plengiResponse3.place.lng_est = placeObj2.getDouble("lng_est");
                        plengiResponse3.place.client_code = clientCode2;
                        plengiResponse3.place.loplatid = loplatid2;
                        if (b.h(this.a) == 4) {
                            if (clientCodePrev == null || !clientCodePrev.equals(clientCode2)) {
                                b.a(this.a, 0);
                                b.a(this.a);
                            } else {
                                b.a(this.a, 5);
                                LoplatLogger.writeLog("== Skip Enter Event because of the same client_code ==");
                            }
                        } else if (clientCodePrev == null && (com.loplat.placeengine.c.a.o(this.a) || (!com.loplat.placeengine.c.a.o(this.a) && accuracy2 > threshold2 && accuracy2 < 1.0f))) {
                            b.a(this.a, plengiResponse3.place);
                            plengiResponse3.type = 2;
                            plengiResponse3.placeEvent = 1;
                            if (accuracy2 < threshold2) {
                                plengiResponse3.enterType = 1;
                            } else if (accuracy2 > threshold2 && accuracy2 < 1.0f) {
                                plengiResponse3.enterType = 0;
                            }
                            Plengi plengi3 = Plengi.getInstance(null);
                            if (plengi3 != null) {
                                LoplatLogger.writeLog("SEND SECOND ENTER EVENT --------------:" + plengiResponse3.place.name);
                                PlengiListener listener5 = plengi3.getListener();
                                if (listener5 != null) {
                                    listener5.listen(plengiResponse3);
                                }
                            } else {
                                LoplatLogger.writeLog("Get Engine Client Error!!!!!!");
                            }
                        }
                    } else if (com.loplat.placeengine.c.a.p(this.a) == 1) {
                        PlengiResponse plengiResponse4 = new PlengiResponse();
                        plengiResponse4.type = 3;
                        plengiResponse4.place = new Place();
                        plengiResponse4.place.name = name2;
                        plengiResponse4.place.tags = tags2;
                        plengiResponse4.place.category = category2;
                        plengiResponse4.place.lat = lat2;
                        plengiResponse4.place.lng = lng2;
                        plengiResponse4.place.floor = floor2;
                        plengiResponse4.place.accuracy = accuracy2;
                        plengiResponse4.place.threshold = threshold2;
                        plengiResponse4.place.lat_est = placeObj2.getDouble("lat_est");
                        plengiResponse4.place.lng_est = placeObj2.getDouble("lng_est");
                        plengiResponse4.place.client_code = clientCode2;
                        plengiResponse4.place.loplatid = loplatid2;
                        Plengi plengi4 = Plengi.getInstance(null);
                        if (plengi4 == null) {
                            LoplatLogger.writeLog("Get Engine Client Error!!!!!!");
                        } else if (accuracy2 > threshold2) {
                            LoplatLogger.printLog("[TRACKER Update]-----------");
                            PlengiListener listener6 = plengi4.getListener();
                            if (listener6 != null) {
                                listener6.listen(plengiResponse4);
                            }
                        } else {
                            PlengiResponse plengiResponseNone = new PlengiResponse();
                            plengiResponseNone.type = 3;
                            plengiResponseNone.place = null;
                            PlengiListener listener7 = plengi4.getListener();
                            if (listener7 != null) {
                                listener7.listen(plengiResponseNone);
                            }
                        }
                        c.a(this.a, plengiResponse4.place);
                    }
                } else if (type.contains("getuuidp")) {
                    PlengiResponse plengiResponse5 = new PlengiResponse();
                    plengiResponse5.type = 4;
                    plengiResponse5.persons = new ArrayList<>();
                    JSONObject uuidpObj = jSONObject.getJSONObject("uuidp");
                    long placeid = uuidpObj.getLong("placeid");
                    long visitcount = uuidpObj.getLong("visitcount");
                    plengiResponse5.uuidp = new Uuidp();
                    plengiResponse5.uuidp.placeid = placeid;
                    plengiResponse5.uuidp.visitcount = visitcount;
                    plengiResponse5.uuidp.similarity = (float) uuidpObj.getDouble("similarity");
                    plengiResponse5.uuidp.description = response;
                    Plengi plengi5 = Plengi.getInstance(null);
                    if (plengi5 != null) {
                        PlengiListener listener8 = plengi5.getListener();
                        if (listener8 != null) {
                            listener8.listen(plengiResponse5);
                        }
                    } else {
                        LoplatLogger.writeLog("Get Engine Client Error!!!!!!");
                    }
                } else if (type.contains("getcolocate")) {
                    PlengiResponse plengiResponse6 = new PlengiResponse();
                    plengiResponse6.type = 5;
                    plengiResponse6.persons = new ArrayList<>();
                    JSONArray personsObj = jSONObject.getJSONArray(NativeProtocol.AUDIENCE_FRIENDS);
                    for (int i = 0; i < personsObj.length(); i++) {
                        plengiResponse6.persons.add(new Person(personsObj.getJSONObject(i).getString("name")));
                    }
                    Plengi plengi6 = Plengi.getInstance(null);
                    if (plengi6 != null) {
                        PlengiListener listener9 = plengi6.getListener();
                        if (listener9 != null) {
                            listener9.listen(plengiResponse6);
                        }
                    } else {
                        LoplatLogger.writeLog("Get Engine Client Error!!!!!!");
                    }
                }
            } catch (JSONException e) {
                e.printStackTrace();
            }
            inputStreamReader.close();
            bufferedReader.close();
        } catch (SocketTimeoutException e2) {
            LoplatLogger.writeLog("Cloud Connection Timeout Error: " + e2.toString());
        } catch (IOException e3) {
            LoplatLogger.writeLog("Cloud Access Error: " + e3);
        } catch (SecurityException e4) {
            LoplatLogger.writeLog("Exception to access Cloud: " + e4);
        }
    }

    private boolean a(Context context) {
        NetworkInfo activeNetworkInfo = ((ConnectivityManager) context.getSystemService("connectivity")).getActiveNetworkInfo();
        return activeNetworkInfo != null && activeNetworkInfo.isConnected();
    }
}