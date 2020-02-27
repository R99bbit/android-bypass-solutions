package com.fasterxml.jackson.databind;

import com.fasterxml.jackson.core.util.InternCache;
import java.io.Serializable;

public class PropertyName implements Serializable {
    public static final PropertyName NO_NAME = new PropertyName(new String(""), null);
    public static final PropertyName USE_DEFAULT = new PropertyName("", null);
    private static final String _NO_NAME = "";
    private static final String _USE_DEFAULT = "";
    private static final long serialVersionUID = 7930806520033045126L;
    protected final String _namespace;
    protected final String _simpleName;

    public PropertyName(String str) {
        this(str, null);
    }

    public PropertyName(String str, String str2) {
        this._simpleName = str == null ? "" : str;
        this._namespace = str2;
    }

    /* access modifiers changed from: protected */
    public Object readResolve() {
        if (this._simpleName == null || "".equals(this._simpleName)) {
            return USE_DEFAULT;
        }
        if (!this._simpleName.equals("") || this._namespace != null) {
            return this;
        }
        return NO_NAME;
    }

    public static PropertyName construct(String str, String str2) {
        if (str == null) {
            str = "";
        }
        if (str2 == null && str.length() == 0) {
            return USE_DEFAULT;
        }
        return new PropertyName(str, str2);
    }

    public PropertyName internSimpleName() {
        if (this._simpleName.length() == 0) {
            return this;
        }
        String intern = InternCache.instance.intern(this._simpleName);
        return intern != this._simpleName ? new PropertyName(intern, this._namespace) : this;
    }

    public PropertyName withSimpleName(String str) {
        if (str == null) {
            str = "";
        }
        return str.equals(this._simpleName) ? this : new PropertyName(str, this._namespace);
    }

    public PropertyName withNamespace(String str) {
        if (str == null) {
            if (this._namespace == null) {
                return this;
            }
        } else if (str.equals(this._namespace)) {
            return this;
        }
        return new PropertyName(this._simpleName, str);
    }

    public String getSimpleName() {
        return this._simpleName;
    }

    public String getNamespace() {
        return this._namespace;
    }

    public boolean hasSimpleName() {
        return this._simpleName.length() > 0;
    }

    public boolean hasSimpleName(String str) {
        if (str == null) {
            return this._simpleName == null;
        }
        return str.equals(this._simpleName);
    }

    public boolean hasNamespace() {
        return this._namespace != null;
    }

    public boolean equals(Object obj) {
        boolean z = true;
        if (obj == this) {
            return true;
        }
        if (obj == null || obj.getClass() != getClass()) {
            return false;
        }
        PropertyName propertyName = (PropertyName) obj;
        if (this._simpleName == null) {
            if (propertyName._simpleName != null) {
                return false;
            }
        } else if (!this._simpleName.equals(propertyName._simpleName)) {
            return false;
        }
        if (this._namespace != null) {
            return this._namespace.equals(propertyName._namespace);
        }
        if (propertyName._namespace != null) {
            z = false;
        }
        return z;
    }

    public int hashCode() {
        if (this._namespace == null) {
            return this._simpleName.hashCode();
        }
        return this._namespace.hashCode() ^ this._simpleName.hashCode();
    }

    public String toString() {
        if (this._namespace == null) {
            return this._simpleName;
        }
        return "{" + this._namespace + "}" + this._simpleName;
    }
}