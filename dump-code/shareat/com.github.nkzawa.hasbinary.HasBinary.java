package com.github.nkzawa.hasbinary;

import java.util.Iterator;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class HasBinary {
    private HasBinary() {
    }

    public static boolean hasBinary(Object data) {
        return _hasBinary(data);
    }

    private static boolean _hasBinary(Object obj) {
        if (obj == null) {
            return false;
        }
        if (obj instanceof byte[]) {
            return true;
        }
        if (obj instanceof JSONArray) {
            JSONArray _obj = (JSONArray) obj;
            int length = _obj.length();
            int i = 0;
            while (i < length) {
                try {
                    if (_hasBinary(_obj.isNull(i) ? null : _obj.get(i))) {
                        return true;
                    }
                    i++;
                } catch (JSONException e) {
                    return false;
                }
            }
            return false;
        } else if (!(obj instanceof JSONObject)) {
            return false;
        } else {
            JSONObject _obj2 = (JSONObject) obj;
            Iterator keys = _obj2.keys();
            while (keys.hasNext()) {
                try {
                    if (_hasBinary(_obj2.get(keys.next()))) {
                        return true;
                    }
                } catch (JSONException e2) {
                    return false;
                }
            }
            return false;
        }
    }
}