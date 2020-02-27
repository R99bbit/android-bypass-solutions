package com.nuvent.shareat.activity.common;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.annotation.UiThread;
import android.support.v4.app.Fragment;
import android.support.v4.app.FragmentActivity;
import android.text.TextUtils;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.TextView;
import com.naver.maps.geometry.LatLng;
import com.naver.maps.map.CameraAnimation;
import com.naver.maps.map.CameraPosition;
import com.naver.maps.map.CameraUpdate;
import com.naver.maps.map.MapFragment;
import com.naver.maps.map.NaverMap;
import com.naver.maps.map.OnMapReadyCallback;
import com.naver.maps.map.UiSettings;
import com.naver.maps.map.overlay.Marker;
import com.naver.maps.map.overlay.OverlayImage;
import com.naver.maps.map.util.FusedLocationSource;
import com.nuvent.shareat.R;
import com.nuvent.shareat.ShareatApp;
import com.nuvent.shareat.activity.BaseActivity;
import com.nuvent.shareat.model.store.StoreDetailModel;
import com.nuvent.shareat.util.ExternalApp;
import com.nuvent.shareat.util.GAEvent;
import java.util.HashMap;

public class NMapActivity extends BaseActivity implements OnClickListener, OnMapReadyCallback {
    private static final int LOCATION_PERMISSION_REQUEST_CODE = 1000;
    private CameraPosition cameraPosition;
    private FusedLocationSource mLocationSource;
    private StoreDetailModel mModel;
    private NaverMap mNaverMap;
    private Marker marker;
    private Marker myPosition;

    public void onBackPressed() {
        finish(R.anim.scale_up, R.anim.modal_exit_animation);
    }

    public void onClickBack(View view) {
        onBackPressed();
    }

    @UiThread
    public void onMapReady(@NonNull NaverMap naverMap) {
        UiSettings uiSettings = naverMap.getUiSettings();
        uiSettings.setLocationButtonEnabled(false);
        uiSettings.setZoomControlEnabled(false);
        this.mNaverMap = naverMap;
        setMapPoint();
    }

    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        if (!this.mLocationSource.onRequestPermissionsResult(requestCode, permissions, grantResults)) {
            super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        }
    }

    public void updateMap(LatLng latLng) {
        this.marker.setPosition(latLng);
        this.marker.setIcon(OverlayImage.fromResource(R.drawable.ic_pin_01));
        this.marker.setMap(this.mNaverMap);
        this.cameraPosition = new CameraPosition(latLng, this.mNaverMap.getMaxZoom() - 3.0d);
        this.mNaverMap.setCameraPosition(this.cameraPosition);
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_map);
        GAEvent.onGAScreenView(this, R.string.ga_store_map);
        if (VERSION.SDK_INT >= 19) {
            findViewById(R.id.statusView).getLayoutParams().height = getStatusBarHeight();
        }
        this.mModel = (StoreDetailModel) getIntent().getSerializableExtra("model");
        if (this.mModel == null) {
            finish();
            return;
        }
        ((TextView) findViewById(R.id.titleLabel)).setText(this.mModel.getPartner_name1());
        ((TextView) findViewById(R.id.addressLabel)).setText(this.mModel.getRoad_addr_1() + this.mModel.getRoad_addr_2());
        findViewById(R.id.myLocationButton).setOnClickListener(this);
        findViewById(R.id.mapLoadButton).setOnClickListener(this);
        this.marker = new Marker();
        MapFragment mapFragment = (MapFragment) getSupportFragmentManager().findFragmentById(R.id.mapFragment);
        if (mapFragment == null) {
            mapFragment = MapFragment.newInstance();
            getSupportFragmentManager().beginTransaction().add((int) R.id.mapFragment, (Fragment) mapFragment).commit();
        }
        mapFragment.getMapAsync(this);
    }

    /* access modifiers changed from: protected */
    public void onStart() {
        super.onStart();
    }

    /* access modifiers changed from: protected */
    public void onResume() {
        super.onResume();
    }

    /* access modifiers changed from: protected */
    public void onPause() {
        super.onPause();
    }

    /* access modifiers changed from: protected */
    public void onDestroy() {
        super.onDestroy();
    }

    private void onLoadMap() {
        setMapPoint();
    }

    public void onClick(View v) {
        switch (v.getId()) {
            case R.id.mapLoadButton /*2131296818*/:
                GAEvent.onGaEvent((Activity) this, (int) R.string.ga_store_map, (int) R.string.ga_ev_click, (int) R.string.ga_store_map_route);
                viewMap();
                return;
            case R.id.myLocationButton /*2131296883*/:
                GAEvent.onGaEvent((Activity) this, (int) R.string.ga_store_map, (int) R.string.ga_ev_click, (int) R.string.ga_store_map_location);
                startMyLocation();
                return;
            default:
                return;
        }
    }

    public void startMyLocation() {
        double longitude = 127.027021d;
        double latitude = 37.4986366d;
        if (ShareatApp.getInstance().getGpsManager().isGetLocation()) {
            longitude = ShareatApp.getInstance().getGpsManager().getLongitude();
            latitude = ShareatApp.getInstance().getGpsManager().getLatitude();
        }
        if (this.myPosition == null) {
            this.myPosition = new Marker();
            this.myPosition.setIcon(OverlayImage.fromResource(R.drawable.my_location_pin));
        }
        this.myPosition.setPosition(new LatLng(latitude, longitude));
        this.myPosition.setMap(this.mNaverMap);
        this.mNaverMap.moveCamera(CameraUpdate.scrollTo(this.myPosition.getPosition()).animate(CameraAnimation.Easing));
    }

    private void setMapPoint() {
        updateMap(new LatLng(Double.valueOf(this.mModel.getMap_y()).doubleValue(), Double.valueOf(this.mModel.getMap_x()).doubleValue()));
    }

    private void viewMap() {
        HashMap<String, String> paramHashMap = new HashMap<>();
        paramHashMap.put("elat", String.valueOf(this.mModel.getMap_y()));
        paramHashMap.put("elng", String.valueOf(this.mModel.getMap_x()));
        paramHashMap.put("etitle", Uri.decode(this.mModel.getPartner_name1()));
        StringBuilder localStringBuilder = new StringBuilder("navermaps://?version=4&appname=nu");
        localStringBuilder.append("&menu=route");
        for (String key : paramHashMap.keySet()) {
            String value = paramHashMap.get(key);
            if (!TextUtils.isEmpty(value)) {
                localStringBuilder.append("&").append(key).append("=").append(value);
            }
        }
        Intent mapIntent = new Intent("android.intent.action.VIEW", Uri.parse(localStringBuilder.toString()));
        mapIntent.addCategory("android.intent.category.BROWSABLE");
        if (!ExternalApp.onInstallApp((FragmentActivity) this, (int) R.string.NAVER_MAP_INSTALL_CONFIRM_MSG, mapIntent, (String) ExternalApp.NAVER_MAP)) {
            startActivity(mapIntent);
        }
    }

    private void stopMyLocation() {
    }
}