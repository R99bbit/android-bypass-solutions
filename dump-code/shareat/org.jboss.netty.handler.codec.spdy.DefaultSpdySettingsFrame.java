package org.jboss.netty.handler.codec.spdy;

import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeMap;
import org.jboss.netty.util.internal.StringUtil;

public class DefaultSpdySettingsFrame implements SpdySettingsFrame {
    private boolean clear;
    private final Map<Integer, Setting> settingsMap = new TreeMap();

    private static final class Setting {
        private boolean persist;
        private boolean persisted;
        private int value;

        Setting(int value2, boolean persist2, boolean persisted2) {
            this.value = value2;
            this.persist = persist2;
            this.persisted = persisted2;
        }

        /* access modifiers changed from: 0000 */
        public int getValue() {
            return this.value;
        }

        /* access modifiers changed from: 0000 */
        public void setValue(int value2) {
            this.value = value2;
        }

        /* access modifiers changed from: 0000 */
        public boolean isPersist() {
            return this.persist;
        }

        /* access modifiers changed from: 0000 */
        public void setPersist(boolean persist2) {
            this.persist = persist2;
        }

        /* access modifiers changed from: 0000 */
        public boolean isPersisted() {
            return this.persisted;
        }

        /* access modifiers changed from: 0000 */
        public void setPersisted(boolean persisted2) {
            this.persisted = persisted2;
        }
    }

    public Set<Integer> getIds() {
        return this.settingsMap.keySet();
    }

    public boolean isSet(int id) {
        return this.settingsMap.containsKey(Integer.valueOf(id));
    }

    public int getValue(int id) {
        Integer key = Integer.valueOf(id);
        if (this.settingsMap.containsKey(key)) {
            return this.settingsMap.get(key).getValue();
        }
        return -1;
    }

    public void setValue(int id, int value) {
        setValue(id, value, false, false);
    }

    public void setValue(int id, int value, boolean persistValue, boolean persisted) {
        if (id < 0 || id > 16777215) {
            throw new IllegalArgumentException("Setting ID is not valid: " + id);
        }
        Integer key = Integer.valueOf(id);
        if (this.settingsMap.containsKey(key)) {
            Setting setting = this.settingsMap.get(key);
            setting.setValue(value);
            setting.setPersist(persistValue);
            setting.setPersisted(persisted);
            return;
        }
        this.settingsMap.put(key, new Setting(value, persistValue, persisted));
    }

    public void removeValue(int id) {
        Integer key = Integer.valueOf(id);
        if (this.settingsMap.containsKey(key)) {
            this.settingsMap.remove(key);
        }
    }

    public boolean isPersistValue(int id) {
        Integer key = Integer.valueOf(id);
        if (this.settingsMap.containsKey(key)) {
            return this.settingsMap.get(key).isPersist();
        }
        return false;
    }

    public void setPersistValue(int id, boolean persistValue) {
        Integer key = Integer.valueOf(id);
        if (this.settingsMap.containsKey(key)) {
            this.settingsMap.get(key).setPersist(persistValue);
        }
    }

    public boolean isPersisted(int id) {
        Integer key = Integer.valueOf(id);
        if (this.settingsMap.containsKey(key)) {
            return this.settingsMap.get(key).isPersisted();
        }
        return false;
    }

    public void setPersisted(int id, boolean persisted) {
        Integer key = Integer.valueOf(id);
        if (this.settingsMap.containsKey(key)) {
            this.settingsMap.get(key).setPersisted(persisted);
        }
    }

    public boolean clearPreviouslyPersistedSettings() {
        return this.clear;
    }

    public void setClearPreviouslyPersistedSettings(boolean clear2) {
        this.clear = clear2;
    }

    private Set<Entry<Integer, Setting>> getSettings() {
        return this.settingsMap.entrySet();
    }

    private void appendSettings(StringBuilder buf) {
        for (Entry<Integer, Setting> e : getSettings()) {
            Setting setting = e.getValue();
            buf.append("--> ");
            buf.append(e.getKey().toString());
            buf.append(':');
            buf.append(setting.getValue());
            buf.append(" (persist value: ");
            buf.append(setting.isPersist());
            buf.append("; persisted: ");
            buf.append(setting.isPersisted());
            buf.append(')');
            buf.append(StringUtil.NEWLINE);
        }
    }

    public String toString() {
        StringBuilder buf = new StringBuilder();
        buf.append(getClass().getSimpleName());
        buf.append(StringUtil.NEWLINE);
        appendSettings(buf);
        buf.setLength(buf.length() - StringUtil.NEWLINE.length());
        return buf.toString();
    }
}