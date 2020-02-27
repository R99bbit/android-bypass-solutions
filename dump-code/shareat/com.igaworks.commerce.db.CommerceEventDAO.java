package com.igaworks.commerce.db;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import java.util.ArrayList;
import java.util.List;

public class CommerceEventDAO {
    public static final String COMMERCE_EVENT_SP_NAME = "CommerceEvents";

    public static SharedPreferences getCommerceEventsSP(Context context) {
        return context.getSharedPreferences(COMMERCE_EVENT_SP_NAME, 0);
    }

    public static void addEvents(Context context, List<String> items) {
        Editor edt = getCommerceEventsSP(context).edit();
        for (String cem : items) {
            edt.putString(cem.toString(), cem.toString());
        }
        edt.commit();
    }

    public static void addEvent(Context context, String item) {
        Editor edt = getCommerceEventsSP(context).edit();
        edt.putString(item, item);
        edt.commit();
    }

    public static List<String> getEvents(Context context) {
        try {
            ArrayList arrayList = new ArrayList(getCommerceEventsSP(context).getAll().values());
            try {
                return arrayList;
            } catch (Exception e) {
                e.printStackTrace();
                return arrayList;
            }
        } catch (Exception e2) {
            e2.printStackTrace();
            try {
            } catch (Exception e3) {
                e3.printStackTrace();
            }
            return null;
        } finally {
            try {
                Editor edt = getCommerceEventsSP(context).edit();
                edt.clear();
                edt.commit();
            } catch (Exception e4) {
                e4.printStackTrace();
            }
        }
    }
}