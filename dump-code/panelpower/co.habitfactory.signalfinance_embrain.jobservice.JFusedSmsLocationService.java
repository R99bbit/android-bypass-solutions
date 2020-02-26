package co.habitfactory.signalfinance_embrain.jobservice;

import android.content.Context;
import android.content.Intent;
import android.location.Location;
import android.os.Bundle;
import android.os.Looper;
import androidx.core.app.SafeJobIntentService;
import androidx.core.content.ContextCompat;
import co.habitfactory.signalfinance_embrain.comm.SignalLibConsts;
import co.habitfactory.signalfinance_embrain.comm.SignalLibPrefs;
import co.habitfactory.signalfinance_embrain.comm.SignalUtil;
import co.habitfactory.signalfinance_embrain.retroapi.APIHelper;
import co.habitfactory.signalfinance_embrain.retroapi.RestfulAdapter;
import co.habitfactory.signalfinance_embrain.retroapi.request.IptUpdateLocation;
import co.habitfactory.signalfinance_embrain.retroapi.response.OptResultDataset;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.GoogleApiClient.Builder;
import com.google.android.gms.common.api.GoogleApiClient.ConnectionCallbacks;
import com.google.android.gms.common.api.GoogleApiClient.OnConnectionFailedListener;
import com.google.android.gms.location.LocationListener;
import com.google.android.gms.location.LocationRequest;
import com.google.android.gms.location.LocationServices;
import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;

public class JFusedSmsLocationService extends SafeJobIntentService implements ConnectionCallbacks, OnConnectionFailedListener, LocationListener, SignalLibConsts {
    private static int DISPLACEMENT = 5;
    private static int FATEST_INTERVAL = 5000;
    static final int JOB_ID = 1003;
    private static int RETRY_COUNT = 0;
    private static int UPDATE_INTERVAL = 10000;
    /* access modifiers changed from: private */
    public final String TAG = JFusedSmsLocationService.class.getSimpleName();
    private Context mContext;
    private GoogleApiClient mGoogleApiClient;
    private Location mLastLocation;
    private LocationRequest mLocationRequest;
    private SignalLibPrefs mPrefs;
    private String mRTimestamp;
    private boolean mRequestingLocationUpdates = false;
    private String mStrSmsId;

    public boolean onStopCurrentWork() {
        return false;
    }

    public void onCreate() {
        super.onCreate();
        this.mPrefs = new SignalLibPrefs(this);
        this.mContext = this;
    }

    public static void enqueueWork(Context context, Intent intent) {
        enqueueWork(context, JFusedSmsLocationService.class, 1003, intent);
    }

    /* access modifiers changed from: protected */
    public void onHandleWork(Intent intent) {
        String str;
        try {
            str = SignalUtil.getUserId(this);
        } catch (Exception e) {
            e.printStackTrace();
            str = "";
        }
        if (str.length() <= 0) {
            SignalUtil.PRINT_LOG(this.TAG, " : userId\uc5c6\uc74c");
            stopSelf();
            return;
        }
        try {
            this.mStrSmsId = intent.getStringExtra("pushId");
        } catch (Exception e2) {
            e2.printStackTrace();
            this.mStrSmsId = null;
        }
        try {
            this.mRTimestamp = intent.getStringExtra("rTimestamp");
        } catch (Exception e3) {
            e3.printStackTrace();
            this.mRTimestamp = null;
        }
        String str2 = this.mStrSmsId;
        if (str2 == null || str2.length() == 0) {
            stopSelf();
        }
        buildGoogleApiClient();
        createLocationRequest();
        try {
            if (this.mGoogleApiClient != null) {
                this.mGoogleApiClient.connect();
            } else {
                stopSelf();
            }
        } catch (Exception e4) {
            e4.printStackTrace();
        }
        this.mRequestingLocationUpdates = true;
        if (this.mGoogleApiClient.isConnected() && this.mRequestingLocationUpdates) {
            startLocationUpdates();
        }
    }

    public void onDestroy() {
        GoogleApiClient googleApiClient = this.mGoogleApiClient;
        if (!(googleApiClient == null || googleApiClient == null)) {
            try {
                if (googleApiClient.isConnected()) {
                    this.mGoogleApiClient.disconnect();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        stopSelf();
        super.onDestroy();
    }

    /* access modifiers changed from: protected */
    public synchronized void buildGoogleApiClient() {
        this.mGoogleApiClient = new Builder(this).addConnectionCallbacks(this).addOnConnectionFailedListener(this).addApi(LocationServices.API).build();
    }

    /* access modifiers changed from: protected */
    public void createLocationRequest() {
        this.mLocationRequest = new LocationRequest();
        this.mLocationRequest.setInterval((long) UPDATE_INTERVAL);
        this.mLocationRequest.setFastestInterval((long) FATEST_INTERVAL);
        this.mLocationRequest.setPriority(100);
        this.mLocationRequest.setSmallestDisplacement((float) DISPLACEMENT);
    }

    /* access modifiers changed from: protected */
    public void startLocationUpdates() {
        try {
            int checkSelfPermission = ContextCompat.checkSelfPermission(this, "android.permission.ACCESS_FINE_LOCATION");
            int checkSelfPermission2 = ContextCompat.checkSelfPermission(this, "android.permission.ACCESS_COARSE_LOCATION");
            if (checkSelfPermission != -1) {
                if (checkSelfPermission2 != -1) {
                    LocationServices.FusedLocationApi.requestLocationUpdates(this.mGoogleApiClient, this.mLocationRequest, (LocationListener) this, Looper.getMainLooper());
                    return;
                }
            }
            stopSelf();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /* access modifiers changed from: protected */
    public void stopLocationUpdates() {
        try {
            LocationServices.FusedLocationApi.removeLocationUpdates(this.mGoogleApiClient, (LocationListener) this);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void onLocationChanged(Location location) {
        this.mLastLocation = location;
        try {
            displayLocation();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /* JADX WARNING: Removed duplicated region for block: B:12:0x002c  */
    /* JADX WARNING: Removed duplicated region for block: B:13:0x0051  */
    private void displayLocation() throws Exception {
        try {
            int checkSelfPermission = ContextCompat.checkSelfPermission(this, "android.permission.ACCESS_FINE_LOCATION");
            int checkSelfPermission2 = ContextCompat.checkSelfPermission(this, "android.permission.ACCESS_COARSE_LOCATION");
            if (checkSelfPermission != -1) {
                if (checkSelfPermission2 != -1) {
                    this.mLastLocation = LocationServices.FusedLocationApi.getLastLocation(this.mGoogleApiClient);
                    if (this.mLastLocation == null) {
                        RETRY_COUNT = 0;
                        this.mRequestingLocationUpdates = false;
                        stopLocationUpdates();
                        sendToServerForUpdate(String.valueOf(this.mLastLocation.getLatitude()), String.valueOf(this.mLastLocation.getLongitude()), this.mLastLocation.getProvider(), "");
                        return;
                    }
                    RETRY_COUNT = 0;
                    this.mRequestingLocationUpdates = false;
                    stopLocationUpdates();
                    sendToServerForUpdate("NF", "NF", "NF", "");
                    return;
                }
            }
            stopSelf();
        } catch (Exception e) {
            e.printStackTrace();
        }
        if (this.mLastLocation == null) {
        }
    }

    public void onConnectionFailed(ConnectionResult connectionResult) {
        if (!this.mGoogleApiClient.isConnected()) {
            this.mGoogleApiClient.connect();
        }
    }

    public void onConnected(Bundle bundle) {
        if (this.mRequestingLocationUpdates) {
            startLocationUpdates();
        }
    }

    public void onConnectionSuspended(int i) {
        this.mGoogleApiClient.connect();
    }

    private void sendToServerForUpdate(String str, String str2, String str3, String str4) throws Exception {
        IptUpdateLocation iptUpdateLocation = new IptUpdateLocation(SignalUtil.getUserId(this.mContext), this.mStrSmsId, str, str2, str3, str4, this.mRTimestamp);
        APIHelper.enqueueWithRetry(RestfulAdapter.getInstance(this).requestUpdateSmsLocation(iptUpdateLocation), 1, new Callback<OptResultDataset>() {
            public void onResponse(Call<OptResultDataset> call, Response<OptResultDataset> response) {
                int code = response.code();
                if (code == 200) {
                    OptResultDataset optResultDataset = (OptResultDataset) response.body();
                    if (optResultDataset != null) {
                        String access$000 = JFusedSmsLocationService.this.TAG;
                        StringBuilder sb = new StringBuilder();
                        sb.append("response");
                        sb.append(String.valueOf(code));
                        SignalUtil.PRINT_LOG(access$000, sb.toString());
                        JFusedSmsLocationService.this.parseResult(optResultDataset);
                        return;
                    }
                    SignalUtil.PRINT_LOG(JFusedSmsLocationService.this.TAG, "response : result null");
                    JFusedSmsLocationService.this.stopSelf();
                    return;
                }
                String access$0002 = JFusedSmsLocationService.this.TAG;
                StringBuilder sb2 = new StringBuilder();
                sb2.append("response : ");
                sb2.append(String.valueOf(code));
                SignalUtil.PRINT_LOG(access$0002, sb2.toString());
            }

            public void onFailure(Call<OptResultDataset> call, Throwable th) {
                String access$000 = JFusedSmsLocationService.this.TAG;
                StringBuilder sb = new StringBuilder();
                sb.append("fail : ");
                sb.append(th.toString());
                SignalUtil.PRINT_LOG(access$000, sb.toString());
                JFusedSmsLocationService.this.stopSelf();
            }
        });
    }

    public void parseResult(OptResultDataset optResultDataset) {
        String str = this.TAG;
        StringBuilder sb = new StringBuilder();
        sb.append("resultcode  : ");
        sb.append(optResultDataset.getResultcode());
        SignalUtil.PRINT_LOG(str, sb.toString());
        String str2 = this.TAG;
        StringBuilder sb2 = new StringBuilder();
        sb2.append("message     : ");
        sb2.append(optResultDataset.getMessage());
        SignalUtil.PRINT_LOG(str2, sb2.toString());
        stopSelf();
    }
}