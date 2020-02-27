package com.fasterxml.jackson.databind.ser.impl;

import com.fasterxml.jackson.databind.ser.BeanPropertyFilter;
import com.fasterxml.jackson.databind.ser.FilterProvider;
import com.fasterxml.jackson.databind.ser.PropertyFilter;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

public class SimpleFilterProvider extends FilterProvider implements Serializable {
    private static final long serialVersionUID = -6305772546718366447L;
    protected boolean _cfgFailOnUnknownId;
    protected PropertyFilter _defaultFilter;
    protected final Map<String, PropertyFilter> _filtersById;

    public SimpleFilterProvider() {
        this(new HashMap());
    }

    /* JADX WARNING: type inference failed for: r3v0, types: [java.util.Map<java.lang.String, ?>, java.util.Map, java.util.Map<java.lang.String, com.fasterxml.jackson.databind.ser.PropertyFilter>] */
    /* JADX WARNING: Unknown variable types count: 1 */
    public SimpleFilterProvider(Map<String, ?> r3) {
        this._cfgFailOnUnknownId = true;
        for (Object obj : r3.values()) {
            if (!(obj instanceof PropertyFilter)) {
                this._filtersById = _convert((Map<String, ?>) r3);
                return;
            }
        }
        this._filtersById = r3;
    }

    private static final Map<String, PropertyFilter> _convert(Map<String, ?> map) {
        HashMap hashMap = new HashMap();
        for (Entry next : map.entrySet()) {
            Object value = next.getValue();
            if (value instanceof PropertyFilter) {
                hashMap.put(next.getKey(), (PropertyFilter) value);
            } else if (value instanceof BeanPropertyFilter) {
                hashMap.put(next.getKey(), _convert((BeanPropertyFilter) value));
            } else {
                throw new IllegalArgumentException("Unrecognized filter type (" + value.getClass().getName() + ")");
            }
        }
        return hashMap;
    }

    private static final PropertyFilter _convert(BeanPropertyFilter beanPropertyFilter) {
        return SimpleBeanPropertyFilter.from(beanPropertyFilter);
    }

    @Deprecated
    public SimpleFilterProvider setDefaultFilter(BeanPropertyFilter beanPropertyFilter) {
        this._defaultFilter = SimpleBeanPropertyFilter.from(beanPropertyFilter);
        return this;
    }

    public SimpleFilterProvider setDefaultFilter(PropertyFilter propertyFilter) {
        this._defaultFilter = propertyFilter;
        return this;
    }

    public SimpleFilterProvider setDefaultFilter(SimpleBeanPropertyFilter simpleBeanPropertyFilter) {
        this._defaultFilter = simpleBeanPropertyFilter;
        return this;
    }

    public PropertyFilter getDefaultFilter() {
        return this._defaultFilter;
    }

    public SimpleFilterProvider setFailOnUnknownId(boolean z) {
        this._cfgFailOnUnknownId = z;
        return this;
    }

    public boolean willFailOnUnknownId() {
        return this._cfgFailOnUnknownId;
    }

    @Deprecated
    public SimpleFilterProvider addFilter(String str, BeanPropertyFilter beanPropertyFilter) {
        this._filtersById.put(str, _convert(beanPropertyFilter));
        return this;
    }

    public SimpleFilterProvider addFilter(String str, PropertyFilter propertyFilter) {
        this._filtersById.put(str, propertyFilter);
        return this;
    }

    public SimpleFilterProvider addFilter(String str, SimpleBeanPropertyFilter simpleBeanPropertyFilter) {
        this._filtersById.put(str, simpleBeanPropertyFilter);
        return this;
    }

    public PropertyFilter removeFilter(String str) {
        return this._filtersById.remove(str);
    }

    @Deprecated
    public BeanPropertyFilter findFilter(Object obj) {
        throw new UnsupportedOperationException("Access to deprecated filters not supported");
    }

    public PropertyFilter findPropertyFilter(Object obj, Object obj2) {
        PropertyFilter propertyFilter = this._filtersById.get(obj);
        if (propertyFilter == null) {
            propertyFilter = this._defaultFilter;
            if (propertyFilter == null && this._cfgFailOnUnknownId) {
                throw new IllegalArgumentException("No filter configured with id '" + obj + "' (type " + obj.getClass().getName() + ")");
            }
        }
        return propertyFilter;
    }
}