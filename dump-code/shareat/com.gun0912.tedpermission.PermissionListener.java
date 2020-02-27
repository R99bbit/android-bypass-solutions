package com.gun0912.tedpermission;

import java.util.List;

public interface PermissionListener {
    void onPermissionDenied(List<String> list);

    void onPermissionGranted();
}