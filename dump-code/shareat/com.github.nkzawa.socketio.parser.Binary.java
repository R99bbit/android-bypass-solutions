package com.github.nkzawa.socketio.parser;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class Binary {
    private static final String KEY_NUM = "num";
    private static final String KEY_PLACEHOLDER = "_placeholder";

    public static class DeconstructedPacket {
        public byte[][] buffers;
        public Packet packet;
    }

    public static DeconstructedPacket deconstructPacket(Packet packet) {
        List<byte[]> buffers = new ArrayList<>();
        packet.data = _deconstructPacket(packet.data, buffers);
        packet.attachments = buffers.size();
        DeconstructedPacket result = new DeconstructedPacket();
        result.packet = packet;
        result.buffers = (byte[][]) buffers.toArray(new byte[buffers.size()][]);
        return result;
    }

    private static Object _deconstructPacket(Object data, List<byte[]> buffers) {
        if (data == null) {
            return null;
        }
        if (data instanceof byte[]) {
            JSONObject placeholder = new JSONObject();
            try {
                placeholder.put(KEY_PLACEHOLDER, true);
                placeholder.put(KEY_NUM, buffers.size());
                buffers.add((byte[]) data);
                return placeholder;
            } catch (JSONException e) {
                return null;
            }
        } else if (data instanceof JSONArray) {
            JSONArray newData = new JSONArray();
            JSONArray _data = (JSONArray) data;
            int len = _data.length();
            int i = 0;
            while (i < len) {
                try {
                    newData.put(i, _deconstructPacket(_data.get(i), buffers));
                    i++;
                } catch (JSONException e2) {
                    return null;
                }
            }
            return newData;
        } else if (!(data instanceof JSONObject)) {
            return data;
        } else {
            JSONObject newData2 = new JSONObject();
            JSONObject _data2 = (JSONObject) data;
            Iterator<String> keys = _data2.keys();
            while (keys.hasNext()) {
                String key = keys.next();
                try {
                    newData2.put(key, _deconstructPacket(_data2.get(key), buffers));
                } catch (JSONException e3) {
                    return null;
                }
            }
            return newData2;
        }
    }

    public static Packet reconstructPacket(Packet packet, byte[][] buffers) {
        packet.data = _reconstructPacket(packet.data, buffers);
        packet.attachments = -1;
        return packet;
    }

    private static Object _reconstructPacket(Object data, byte[][] buffers) {
        if (data instanceof JSONArray) {
            JSONArray _data = (JSONArray) data;
            int len = _data.length();
            int i = 0;
            while (i < len) {
                try {
                    _data.put(i, _reconstructPacket(_data.get(i), buffers));
                    i++;
                } catch (JSONException e) {
                    return null;
                }
            }
            return _data;
        } else if (!(data instanceof JSONObject)) {
            return data;
        } else {
            JSONObject _data2 = (JSONObject) data;
            if (_data2.optBoolean(KEY_PLACEHOLDER)) {
                int num = _data2.optInt(KEY_NUM, -1);
                if (num < 0 || num >= buffers.length) {
                    return null;
                }
                return buffers[num];
            }
            Iterator<String> keys = _data2.keys();
            while (keys.hasNext()) {
                String key = keys.next();
                try {
                    _data2.put(key, _reconstructPacket(_data2.get(key), buffers));
                } catch (JSONException e2) {
                    return null;
                }
            }
            return _data2;
        }
    }
}