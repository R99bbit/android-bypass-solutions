package com.igaworks.util.image;

import android.util.Log;
import com.igaworks.core.IgawConstant;
import com.igaworks.impl.CommonFrameworkImpl;
import io.fabric.sdk.android.services.network.HttpRequest;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URL;

public class HttpRequestHelper {
    HttpURLConnection httpConn;

    public File download(String fileURL, File toFile) throws IOException, SocketTimeoutException {
        InputStream inputStream;
        try {
            this.httpConn = (HttpURLConnection) new URL(fileURL).openConnection();
            this.httpConn.setReadTimeout(15000);
            this.httpConn.setConnectTimeout(15000);
            this.httpConn.setRequestMethod(HttpRequest.METHOD_GET);
            int responseCode = this.httpConn.getResponseCode();
            if (responseCode == 200) {
                inputStream = this.httpConn.getInputStream();
                IOUtils.copy(inputStream, toFile);
                IOUtils.close(inputStream);
                this.httpConn.disconnect();
                return toFile;
            }
            Log.d(IgawConstant.QA_TAG, "No file to download. Server replied HTTP code: " + responseCode);
            throw new IOException("invalid response code:" + responseCode);
        } catch (SocketTimeoutException e1) {
            try {
                if (CommonFrameworkImpl.isTest) {
                    Log.e(IgawConstant.QA_TAG, "HttpRequestHelper SocketTimeoutException: " + e1.getMessage());
                }
                throw e1;
            } catch (Throwable th) {
                this.httpConn.disconnect();
                throw th;
            }
        } catch (IOException e2) {
            if (CommonFrameworkImpl.isTest) {
                Log.e(IgawConstant.QA_TAG, "HttpRequestHelper IOException: " + e2.getMessage());
            }
            throw e2;
        } catch (Throwable th2) {
            IOUtils.close(inputStream);
            throw th2;
        }
    }

    public static HttpRequestHelper getInstance() {
        return new HttpRequestHelper();
    }
}