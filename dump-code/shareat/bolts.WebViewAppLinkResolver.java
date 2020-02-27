package bolts;

import android.content.Context;
import android.net.Uri;
import android.webkit.JavascriptInterface;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import bolts.AppLink.Target;
import bolts.Task.TaskCompletionSource;
import com.facebook.appevents.AppEventsConstants;
import com.kakao.auth.helper.ServerProtocol;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class WebViewAppLinkResolver implements AppLinkResolver {
    private static final String KEY_AL_VALUE = "value";
    private static final String KEY_ANDROID = "android";
    private static final String KEY_APP_NAME = "app_name";
    private static final String KEY_CLASS = "class";
    private static final String KEY_PACKAGE = "package";
    private static final String KEY_SHOULD_FALLBACK = "should_fallback";
    private static final String KEY_URL = "url";
    private static final String KEY_WEB = "web";
    private static final String KEY_WEB_URL = "url";
    private static final String META_TAG_PREFIX = "al";
    private static final String PREFER_HEADER = "Prefer-Html-Meta-Tags";
    private static final String TAG_EXTRACTION_JAVASCRIPT = "javascript:boltsWebViewAppLinkResolverResult.setValue((function() {  var metaTags = document.getElementsByTagName('meta');  var results = [];  for (var i = 0; i < metaTags.length; i++) {    var property = metaTags[i].getAttribute('property');    if (property && property.substring(0, 'al:'.length) === 'al:') {      var tag = { \"property\": metaTags[i].getAttribute('property') };      if (metaTags[i].hasAttribute('content')) {        tag['content'] = metaTags[i].getAttribute('content');      }      results.push(tag);    }  }  return JSON.stringify(results);})())";
    /* access modifiers changed from: private */
    public final Context context;

    public WebViewAppLinkResolver(Context context2) {
        this.context = context2;
    }

    public Task<AppLink> getAppLinkFromUrlInBackground(final Uri url) {
        final Capture<String> content = new Capture<>();
        final Capture<String> contentType = new Capture<>();
        return Task.callInBackground(new Callable<Void>() {
            public Void call() throws Exception {
                URL currentURL = new URL(url.toString());
                URLConnection connection = null;
                while (currentURL != null) {
                    connection = currentURL.openConnection();
                    if (connection instanceof HttpURLConnection) {
                        ((HttpURLConnection) connection).setInstanceFollowRedirects(true);
                    }
                    connection.setRequestProperty(WebViewAppLinkResolver.PREFER_HEADER, WebViewAppLinkResolver.META_TAG_PREFIX);
                    connection.connect();
                    if (connection instanceof HttpURLConnection) {
                        HttpURLConnection httpConnection = (HttpURLConnection) connection;
                        if (httpConnection.getResponseCode() < 300 || httpConnection.getResponseCode() >= 400) {
                            currentURL = null;
                        } else {
                            currentURL = new URL(httpConnection.getHeaderField("Location"));
                            httpConnection.disconnect();
                        }
                    } else {
                        currentURL = null;
                    }
                }
                try {
                    content.set(WebViewAppLinkResolver.readFromConnection(connection));
                    contentType.set(connection.getContentType());
                    return null;
                } finally {
                    if (connection instanceof HttpURLConnection) {
                        ((HttpURLConnection) connection).disconnect();
                    }
                }
            }
        }).onSuccessTask((Continuation<TResult, Task<TContinuationResult>>) new Continuation<Void, Task<JSONArray>>() {
            public Task<JSONArray> then(Task<Void> task) throws Exception {
                final TaskCompletionSource create = Task.create();
                WebView webView = new WebView(WebViewAppLinkResolver.this.context);
                webView.getSettings().setJavaScriptEnabled(true);
                webView.setNetworkAvailable(false);
                webView.setWebViewClient(new WebViewClient() {
                    private boolean loaded = false;

                    private void runJavaScript(WebView view) {
                        if (!this.loaded) {
                            this.loaded = true;
                            view.loadUrl(WebViewAppLinkResolver.TAG_EXTRACTION_JAVASCRIPT);
                        }
                    }

                    public void onPageFinished(WebView view, String url) {
                        super.onPageFinished(view, url);
                        runJavaScript(view);
                    }

                    public void onLoadResource(WebView view, String url) {
                        super.onLoadResource(view, url);
                        runJavaScript(view);
                    }
                });
                webView.addJavascriptInterface(new Object() {
                    @JavascriptInterface
                    public void setValue(String value) {
                        try {
                            create.trySetResult(new JSONArray(value));
                        } catch (JSONException e) {
                            create.trySetError(e);
                        }
                    }
                }, "boltsWebViewAppLinkResolverResult");
                String inferredContentType = null;
                if (contentType.get() != null) {
                    inferredContentType = ((String) contentType.get()).split(";")[0];
                }
                webView.loadDataWithBaseURL(url.toString(), (String) content.get(), inferredContentType, null, null);
                return create.getTask();
            }
        }, Task.UI_THREAD_EXECUTOR).onSuccess(new Continuation<JSONArray, AppLink>() {
            public AppLink then(Task<JSONArray> task) throws Exception {
                return WebViewAppLinkResolver.makeAppLinkFromAlData(WebViewAppLinkResolver.parseAlData((JSONArray) task.getResult()), url);
            }
        });
    }

    /* access modifiers changed from: private */
    public static Map<String, Object> parseAlData(JSONArray dataArray) throws JSONException {
        Map map;
        HashMap<String, Object> al = new HashMap<>();
        for (int i = 0; i < dataArray.length(); i++) {
            JSONObject tag = dataArray.getJSONObject(i);
            String[] nameComponents = tag.getString("property").split(":");
            if (nameComponents[0].equals(META_TAG_PREFIX)) {
                Map map2 = al;
                for (int j = 1; j < nameComponents.length; j++) {
                    List<Map<String, Object>> children = (List) map2.get(nameComponents[j]);
                    if (children == null) {
                        children = new ArrayList<>();
                        map2.put(nameComponents[j], children);
                    }
                    if (children.size() > 0) {
                        map = children.get(children.size() - 1);
                    } else {
                        map = null;
                    }
                    if (map == null || j == nameComponents.length - 1) {
                        map = new HashMap();
                        children.add(map);
                    }
                    map2 = map;
                }
                if (tag.has(ServerProtocol.CONTENT_KEY)) {
                    if (tag.isNull(ServerProtocol.CONTENT_KEY)) {
                        map2.put("value", null);
                    } else {
                        map2.put("value", tag.getString(ServerProtocol.CONTENT_KEY));
                    }
                }
            }
        }
        return al;
    }

    private static List<Map<String, Object>> getAlList(Map<String, Object> map, String key) {
        List<Map<String, Object>> result = (List) map.get(key);
        if (result == null) {
            return Collections.emptyList();
        }
        return result;
    }

    /* access modifiers changed from: private */
    public static AppLink makeAppLinkFromAlData(Map<String, Object> appLinkDict, Uri destination) {
        ArrayList arrayList = new ArrayList();
        List<Map<String, Object>> platformMapList = (List) appLinkDict.get("android");
        if (platformMapList == null) {
            platformMapList = Collections.emptyList();
        }
        for (Map next : platformMapList) {
            List<Map<String, Object>> urls = getAlList(next, "url");
            List<Map<String, Object>> packages = getAlList(next, "package");
            List<Map<String, Object>> classes = getAlList(next, KEY_CLASS);
            List<Map<String, Object>> appNames = getAlList(next, "app_name");
            int maxCount = Math.max(urls.size(), Math.max(packages.size(), Math.max(classes.size(), appNames.size())));
            int i = 0;
            while (i < maxCount) {
                Target target = new Target((String) (packages.size() > i ? packages.get(i).get("value") : null), (String) (classes.size() > i ? classes.get(i).get("value") : null), tryCreateUrl((String) (urls.size() > i ? urls.get(i).get("value") : null)), (String) (appNames.size() > i ? appNames.get(i).get("value") : null));
                arrayList.add(target);
                i++;
            }
        }
        Uri webUrl = destination;
        List<Map<String, Object>> webMapList = (List) appLinkDict.get("web");
        if (webMapList != null && webMapList.size() > 0) {
            Map<String, Object> webMap = (Map) webMapList.get(0);
            List<Map<String, Object>> urls2 = (List) webMap.get("url");
            List<Map<String, Object>> shouldFallbacks = (List) webMap.get(KEY_SHOULD_FALLBACK);
            if (shouldFallbacks != null && shouldFallbacks.size() > 0) {
                if (Arrays.asList(new String[]{"no", "false", AppEventsConstants.EVENT_PARAM_VALUE_NO}).contains(((String) ((Map) shouldFallbacks.get(0)).get("value")).toLowerCase())) {
                    webUrl = null;
                }
            }
            if (!(webUrl == null || urls2 == null || urls2.size() <= 0)) {
                webUrl = tryCreateUrl((String) ((Map) urls2.get(0)).get("value"));
            }
        }
        AppLink appLink = new AppLink(destination, arrayList, webUrl);
        return appLink;
    }

    private static Uri tryCreateUrl(String urlString) {
        if (urlString == null) {
            return null;
        }
        return Uri.parse(urlString);
    }

    /* access modifiers changed from: private */
    public static String readFromConnection(URLConnection connection) throws IOException {
        InputStream stream;
        if (connection instanceof HttpURLConnection) {
            HttpURLConnection httpConnection = (HttpURLConnection) connection;
            try {
                stream = connection.getInputStream();
            } catch (Exception e) {
                stream = httpConnection.getErrorStream();
            }
        } else {
            stream = connection.getInputStream();
        }
        try {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            while (true) {
                int read = stream.read(buffer);
                if (read == -1) {
                    break;
                }
                output.write(buffer, 0, read);
            }
            String charset = connection.getContentEncoding();
            if (charset == null) {
                String[] arr$ = connection.getContentType().split(";");
                int len$ = arr$.length;
                int i$ = 0;
                while (true) {
                    if (i$ >= len$) {
                        break;
                    }
                    String part = arr$[i$].trim();
                    if (part.startsWith("charset=")) {
                        charset = part.substring("charset=".length());
                        break;
                    }
                    i$++;
                }
                if (charset == null) {
                    charset = "UTF-8";
                }
            }
            return new String(output.toByteArray(), charset);
        } finally {
            stream.close();
        }
    }
}