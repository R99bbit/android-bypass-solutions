package com.ning.http.client.providers.grizzly;

import com.ning.http.client.AsyncHttpProviderConfig;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

public class GrizzlyAsyncHttpProviderConfig implements AsyncHttpProviderConfig<Property, Object> {
    private final Map<Property, Object> attributes = new HashMap();

    public enum Property {
        TRANSPORT_CUSTOMIZER(TransportCustomizer.class),
        MAX_HTTP_PACKET_HEADER_SIZE(Integer.class, Integer.valueOf(8192)),
        BUFFER_WEBSOCKET_FRAGMENTS(Boolean.class, Boolean.valueOf(true));
        
        final Object defaultValue;
        final Class<?> type;

        private Property(Class<?> type2, Object defaultValue2) {
            this.type = type2;
            this.defaultValue = defaultValue2;
        }

        private Property(Class<?> type2) {
            this(r2, r3, type2, null);
        }

        /* access modifiers changed from: 0000 */
        public boolean hasDefaultValue() {
            return this.defaultValue != null;
        }
    }

    public AsyncHttpProviderConfig addProperty(Property name, Object value) {
        if (name != null) {
            if (value == null) {
                if (name.hasDefaultValue()) {
                    value = name.defaultValue;
                }
            } else if (!name.type.isAssignableFrom(value.getClass())) {
                throw new IllegalArgumentException(String.format("The value of property [%s] must be of type [%s].  Type of value provided: [%s].", new Object[]{name.name(), name.type.getName(), value.getClass().getName()}));
            }
            this.attributes.put(name, value);
        }
        return this;
    }

    public Object getProperty(Property name) {
        Object ret = this.attributes.get(name);
        if (ret != null || !name.hasDefaultValue()) {
            return ret;
        }
        return name.defaultValue;
    }

    public Object removeProperty(Property name) {
        if (name == null) {
            return null;
        }
        return this.attributes.remove(name);
    }

    public Set<Entry<Property, Object>> propertiesSet() {
        return this.attributes.entrySet();
    }
}