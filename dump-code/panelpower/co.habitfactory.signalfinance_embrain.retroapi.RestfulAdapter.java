package co.habitfactory.signalfinance_embrain.retroapi;

import android.content.Context;
import co.habitfactory.signalfinance_embrain.comm.SignalLibConsts;
import co.habitfactory.signalfinance_embrain.comm.SignalUtil;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.concurrent.TimeUnit;
import okhttp3.Interceptor;
import okhttp3.Interceptor.Chain;
import okhttp3.OkHttpClient.Builder;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.logging.HttpLoggingInterceptor;
import okhttp3.logging.HttpLoggingInterceptor.Level;
import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;

public class RestfulAdapter implements SignalLibConsts {
    public static final int CONNECT_TIMEOUT = 60;
    private static APIClient Interface = null;
    public static final int READ_TIMEOUT = 60;
    public static final int WRITE_TIMEOUT = 60;
    private static Builder httpClient;

    public static synchronized APIClient getInstance(final Context context) {
        APIClient aPIClient;
        synchronized (RestfulAdapter.class) {
            try {
                if (Interface == null) {
                    httpClient = new Builder().connectTimeout(60, TimeUnit.SECONDS).writeTimeout(60, TimeUnit.SECONDS).readTimeout(60, TimeUnit.SECONDS);
                    new HttpLoggingInterceptor().setLevel(Level.BODY);
                    httpClient.addInterceptor(new Interceptor() {
                        public Response intercept(Chain chain) throws IOException {
                            String str;
                            String str2 = "";
                            try {
                                str = URLEncoder.encode(new SimpleDateFormat("yyyy.MM.dd HH:mm:ss.SSS_zzzz_Z_MMMM_EEEE").format(new Date()), "UTF-8");
                            } catch (UnsupportedEncodingException e) {
                                e.printStackTrace();
                                str = str2;
                            }
                            try {
                                str2 = SignalUtil.NULL_TO_STRING(SignalUtil.getUserId(context));
                            } catch (Exception e2) {
                                e2.printStackTrace();
                            }
                            Request request = chain.request();
                            Request.Builder header = request.newBuilder().header("Accept-Charset", "UTF-8").header("Content-type", "application/json").header("PD", "embrain").header("CT", str);
                            StringBuilder sb = new StringBuilder();
                            sb.append("AP_");
                            sb.append(System.getProperty("http.agent"));
                            sb.append("_VS:");
                            sb.append(SignalLibConsts.g_AppVersion);
                            try {
                                return chain.proceed(header.header("UA", sb.toString()).header("VS", SignalLibConsts.g_AppVersion).header("USERID", str2).method(request.method(), request.body()).build());
                            } catch (IllegalArgumentException e3) {
                                e3.printStackTrace();
                                return null;
                            }
                        }
                    });
                    Interface = (APIClient) new Retrofit.Builder().baseUrl(SignalUtil.getServerUrl(context)).client(httpClient.build()).addConverterFactory(GsonConverterFactory.create()).build().create(APIClient.class);
                }
                aPIClient = Interface;
            }
        }
        return aPIClient;
    }
}