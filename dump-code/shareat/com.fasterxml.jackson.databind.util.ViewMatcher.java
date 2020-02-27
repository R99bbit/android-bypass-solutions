package com.fasterxml.jackson.databind.util;

import java.io.Serializable;

public abstract class ViewMatcher {

    private static final class Empty extends ViewMatcher implements Serializable {
        static final Empty instance = new Empty();
        private static final long serialVersionUID = 1;

        private Empty() {
        }

        public boolean isVisibleForView(Class<?> cls) {
            return false;
        }
    }

    private static final class Multi extends ViewMatcher implements Serializable {
        private static final long serialVersionUID = 1;
        private final Class<?>[] _views;

        public Multi(Class<?>[] clsArr) {
            this._views = clsArr;
        }

        public boolean isVisibleForView(Class<?> cls) {
            for (Class<?> cls2 : this._views) {
                if (cls == cls2 || cls2.isAssignableFrom(cls)) {
                    return true;
                }
            }
            return false;
        }
    }

    private static final class Single extends ViewMatcher implements Serializable {
        private static final long serialVersionUID = 1;
        private final Class<?> _view;

        public Single(Class<?> cls) {
            this._view = cls;
        }

        public boolean isVisibleForView(Class<?> cls) {
            return cls == this._view || this._view.isAssignableFrom(cls);
        }
    }

    public abstract boolean isVisibleForView(Class<?> cls);

    public static ViewMatcher construct(Class<?>[] clsArr) {
        if (clsArr == null) {
            return Empty.instance;
        }
        switch (clsArr.length) {
            case 0:
                return Empty.instance;
            case 1:
                return new Single(clsArr[0]);
            default:
                return new Multi(clsArr);
        }
    }
}