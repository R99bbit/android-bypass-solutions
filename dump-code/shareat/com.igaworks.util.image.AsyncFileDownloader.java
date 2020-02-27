package com.igaworks.util.image;

import android.content.Context;
import java.io.File;
import java.io.IOException;
import org.jboss.netty.handler.codec.http.multipart.DiskFileUpload;

public class AsyncFileDownloader {
    private Context context;

    public AsyncFileDownloader(Context context2) {
        this.context = context2;
    }

    public void download(String url, AsyncCallback<File> callback) {
        download(url, null, callback);
    }

    public void download(String url, File destination, AsyncCallback<File> callback) {
        try {
            runAsyncDownload(url, getDestinationIfNotNullOrCreateTemp(destination, callback), callback);
        } catch (IOException e) {
            callback.exceptionOccured(e);
        }
    }

    private File getDestinationIfNotNullOrCreateTemp(File destination, AsyncCallback<File> asyncCallback) throws IOException {
        return destination != null ? destination : createTemporaryFile();
    }

    private File createTemporaryFile() throws IOException {
        return File.createTempFile("afd", DiskFileUpload.postfix, this.context.getCacheDir());
    }

    private void runAsyncDownload(String url, File destination, AsyncCallback<File> callback) {
        new AsyncExecutor().setCallable(new FileDownloadCallable<>(url, destination)).setCallback(callback).execute(new Void[0]);
    }
}