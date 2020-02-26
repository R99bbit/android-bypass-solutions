package com.loplat.placeengine;

public interface OnPlengiListener {
    void onFail(PlengiResponse plengiResponse);

    void onSuccess(PlengiResponse plengiResponse);
}