package com.gun0912.tedpermission;

import com.gun0912.tedpermission.util.ObjectUtils;
import java.util.List;

public class TedPermissionResult {
    private List<String> deniedPermissions;
    private boolean granted;

    public TedPermissionResult(List<String> deniedPermissions2) {
        this.granted = ObjectUtils.isEmpty(deniedPermissions2);
        this.deniedPermissions = deniedPermissions2;
    }

    public boolean isGranted() {
        return this.granted;
    }

    public List<String> getDeniedPermissions() {
        return this.deniedPermissions;
    }
}