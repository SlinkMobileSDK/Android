package jp.co.secioss.lib;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;

import jp.co.secioss.auth.SeciossAuthActivity;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.webkit.CookieManager;

/**
 * This class implements the HTTP requests send in background other than in the WebView.
 *
 * Implemented by HttpURLConnection Since HttpClient was deprecated in API level 22.
 *
 * @author Shuu Shisen <shuu.shisen@secioss.co.jp>
 * @copyright 2016 SECIOSS, INC.
 * @see http://www.secioss.co.jp
 */
public class SeciossHttpAsyncTask extends AsyncTask<String, Integer, String> {

    private Handler mHandler;
    private boolean mRedirect;
    private String mReturnType;
    private CookieManager mCookieManager;
    private HostnameVerifier mHostnameVerifier;
    private SSLSocketFactory mSSLSocketFactory;

    private String mSessKey;
    private String mSessVal;
    private String mMimeType = "text/html";
    private String mEncoding = "UTF-8";

    /**
     * SeciossHttpAsyncTask construct method
     * @param handler handler for AsyncTask
     * @param redirect flag if follow redirects
     * @param returnType return type of the result
     * @param sessParam parameter name for session id
     * @param cookieManager cookie manager for the requests and responses
     * @param hostnameVerifier custom hostname verifier
     * @param sslSocketFactory custom SSL sockets properties
     */
    public SeciossHttpAsyncTask(Handler handler, boolean redirect, String returnType, String sessParam, CookieManager cookieManager, HostnameVerifier hostnameVerifier, SSLSocketFactory sslSocketFactory) {
        mHandler = handler;
        mRedirect = redirect;
        mReturnType = returnType;
        mSessKey = sessParam;
        mCookieManager = cookieManager;
        mHostnameVerifier = hostnameVerifier;
        mSSLSocketFactory = sslSocketFactory;
    }

    @Override
    protected String doInBackground(String... params) {
        String url = params[0];
        String post = "";
        if (null != url && !"".equals(url) && url.indexOf("?") > 0) {
            if (url.indexOf("?") > 0) {
                post = url.substring(url.indexOf("?") + 1);
            }

            // Retrieve session id from url
            if (url.indexOf("?" + mSessKey + "=") > 0) {
                mSessVal = url.substring(url.indexOf("?" + mSessKey + "=") + (mSessKey.length()+2));
            }
            else if (url.indexOf("&" + mSessKey + "=") > 0) {
                mSessVal = url.substring(url.indexOf("&" + mSessKey + "=") + (mSessKey.length()+2));
            }
            if (null != mSessVal && mSessVal.indexOf("&") > 0) {
                mSessVal = mSessVal.substring(0, mSessVal.indexOf("&"));
            }
        }

        String errors = null;
        String headers = null;
        String location = null;
        String response = null;
        HttpURLConnection conn = null;
        BufferedInputStream in = null;
        BufferedWriter writer = null;
        BufferedReader reader = null;

        try {
            URL urlObj = new URL(url);
            String ptcl = urlObj.getProtocol();
            String host = urlObj.getHost();
            String port = urlObj.getPort() + "";
            if ("-1".equals(port)) {
                port = "";
            }
            else {
                port = ":" + port;
            }

            // サーバへPOSTで送信
            if (url.startsWith("https")) {
                conn = (HttpsURLConnection) urlObj.openConnection();
                if (null != mHostnameVerifier) {
                    ((HttpsURLConnection) conn).setHostnameVerifier(mHostnameVerifier);
                }
                if (null != mSSLSocketFactory) {
                    ((HttpsURLConnection) conn).setSSLSocketFactory(mSSLSocketFactory);
                }
            }
            else if (url.startsWith("http")) {
                conn = (HttpURLConnection) urlObj.openConnection();
            }

            conn.setRequestProperty("Cookie", mCookieManager.getCookie(url));
            conn.setRequestMethod("POST");
            conn.setInstanceFollowRedirects(mRedirect);
            conn.setDoOutput(true);
            conn.setDoInput(true);
            conn.setConnectTimeout(30000);
            conn.setReadTimeout(30000);
            writer = new BufferedWriter(new OutputStreamWriter(conn.getOutputStream()));
            writer.write(post);
            writer.flush();
            writer.close();

            int code = conn.getResponseCode();
            // 301=HttpURLConnection.HTTP_MOVED_PERM 302=HttpURLConnection.HTTP_MOVED_TEMP
            if (code == 301 || code == 302 || code == 307) {
                // Force return type to url
                mReturnType = SeciossAuthActivity.VAL_TYPE_URL;

                location = conn.getHeaderField("Location");
                if (null == location) {
                    location = "";
                }
                else if (location.startsWith("/")) {
                    location = ptcl + "://" + host + port + location;
                }
                response = location;
            }
            else if (code == HttpURLConnection.HTTP_OK) {

                // Retrieve Headers
                Map<String, List<String>> headerFields = conn.getHeaderFields();
                if (null != headerFields) {
                    int i = 0;
                    for (Map.Entry<String, List<String>> entry : headerFields.entrySet()) {
                        String key = entry.getKey();
                        List<String> values = entry.getValue();
                        if (null != values && values.size() > 0) {
                            for (String value : values) {
                                // Retrieve Cookies
                                if ("Set-Cookie".equals(key)) {
                                    mCookieManager.setCookie(url, value);
                                }
                                // Retrieve all header fields
                                if (i == 0) {
                                    if (null == key) {
                                        headers = value;
                                    }
                                    else {
                                        headers = key + ": " + value;
                                    }
                                }
                                else {
                                    if (null == key) {
                                        headers += "\n" + value;
                                    }
                                    else {
                                        headers += "\n" + key + ": " + value;
                                    }
                                }
                                i++;
                            }
                        }
                        else {
                            if (i == 0) {
                                if (null != key) {
                                    headers = key + ": ";
                                }
                            }
                            else {
                                if (null != key) {
                                    headers += "\n" + key + ": ";
                                }
                            }
                        }
                        i++;
                    }
                }

                // Retrieve Contents
                if (SeciossAuthActivity.VAL_TYPE_CONTENT.equalsIgnoreCase(mReturnType) || SeciossAuthActivity.VAL_TYPE_HTM.equalsIgnoreCase(mReturnType)) {
                    String contentType = conn.getContentType();
                    if (null != contentType && !"".equals(contentType)) {
                        if (contentType.indexOf(";") > 0) {
                            mMimeType = contentType.substring(0, contentType.indexOf(";"));
                        }
                        if (contentType.indexOf("charset=") > 0) {
                            mEncoding = contentType.substring(contentType.indexOf("charset=") + 8);
                        }
                    }

                    in = new BufferedInputStream(conn.getInputStream());
                    reader = new BufferedReader(new InputStreamReader(in, mEncoding));
                    StringBuffer buffer = new StringBuffer();
                    String line = reader.readLine();
                    while (line != null) {
                        buffer.append(line);
                        buffer.append("\n");
                        line = reader.readLine();
                    }
                    response = buffer.toString();
                }

                else if (SeciossAuthActivity.VAL_TYPE_HEADER.equalsIgnoreCase(mReturnType)) {
                    response = headers;
                }
                else if (SeciossAuthActivity.VAL_TYPE_COOKIE.equalsIgnoreCase(mReturnType)) {
                    response = mCookieManager.getCookie(url);
                }
            }
            else {
                errors = conn.getResponseMessage();
            }
        }
        catch (Exception e) {
            errors = e.toString();
        }
        finally {
            if (conn != null) {
                conn.disconnect();
            }
            if (in != null) {
                try {
                    in.close();
                }
                catch (IOException e) {
                }
            }
            if (writer != null) {
                try {
                    writer.close();
                }
                catch (IOException e) {
                }
            }
            if (reader != null) {
                try {
                    reader.close();
                }
                catch (IOException e) {
                }
            }
            if (null != errors) {
                response = errors;
            }
        }

        return response;
    }

    @Override
    protected void onPostExecute(String result) {
        if (null != mHandler) {
            Bundle bundle = new Bundle();
            bundle.putString("data", result);
            bundle.putString("sessid", mSessVal);
            bundle.putString("mimeType", mMimeType);
            bundle.putString("encoding", mEncoding);

            Message msg = new Message();
            msg.setData(bundle);

            if (SeciossAuthActivity.VAL_TYPE_HTM.equalsIgnoreCase(mReturnType)) {
                msg.what = SeciossAuthActivity.MSG_CLIENTCERT_HTM;
            }
            else if (SeciossAuthActivity.VAL_TYPE_URL.equalsIgnoreCase(mReturnType)) {
                msg.what = SeciossAuthActivity.MSG_CLIENTCERT_URL;
            }
            else {
                msg.what = SeciossAuthActivity.MSG_NORMALDONE;
            }
            mHandler.sendMessage(msg);
        }
    }

}
