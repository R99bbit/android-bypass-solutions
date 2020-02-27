package com.fasterxml.jackson.databind;

import java.io.Serializable;

public class PropertyMetadata implements Serializable {
    public static final PropertyMetadata STD_OPTIONAL = new PropertyMetadata(Boolean.FALSE, null);
    public static final PropertyMetadata STD_REQUIRED = new PropertyMetadata(Boolean.TRUE, null);
    public static final PropertyMetadata STD_REQUIRED_OR_OPTIONAL = new PropertyMetadata(null, null);
    private static final long serialVersionUID = -1;
    protected final String _description;
    protected final Boolean _required;

    protected PropertyMetadata(Boolean bool, String str) {
        this._required = bool;
        this._description = str;
    }

    public static PropertyMetadata construct(boolean z, String str) {
        PropertyMetadata propertyMetadata = z ? STD_REQUIRED : STD_OPTIONAL;
        if (str != null) {
            return propertyMetadata.withDescription(str);
        }
        return propertyMetadata;
    }

    /* access modifiers changed from: protected */
    public Object readResolve() {
        if (this._description != null) {
            return this;
        }
        if (this._required == null) {
            return STD_REQUIRED_OR_OPTIONAL;
        }
        return this._required.booleanValue() ? STD_REQUIRED : STD_OPTIONAL;
    }

    public PropertyMetadata withDescription(String str) {
        return new PropertyMetadata(this._required, str);
    }

    public PropertyMetadata withRequired(Boolean bool) {
        if (bool == null) {
            if (this._required == null) {
                return this;
            }
        } else if (this._required != null && this._required.booleanValue() == bool.booleanValue()) {
            return this;
        }
        return new PropertyMetadata(bool, this._description);
    }

    public String getDescription() {
        return this._description;
    }

    public boolean isRequired() {
        return this._required != null && this._required.booleanValue();
    }

    public Boolean getRequired() {
        return this._required;
    }
}