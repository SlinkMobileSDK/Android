package jp.co.secioss.auth;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.ref.WeakReference;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import jp.co.secioss.ShibSample.R;
import jp.co.secioss.lib.SeciossHttpAsyncTask;
import jp.co.secioss.lib.SeciossTrustManager;
import android.annotation.SuppressLint;
import android.annotation.TargetApi;
import android.app.Activity;
import android.content.Intent;
import android.graphics.Bitmap;
import android.net.http.SslError;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.util.Base64;
import android.util.Log;
import android.view.KeyEvent;
import android.webkit.ClientCertRequest;
import android.webkit.CookieManager;
import android.webkit.JavascriptInterface;
import android.webkit.SslErrorHandler;
import android.webkit.WebChromeClient;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.RelativeLayout;
import android.widget.Toast;

/**
 * Main class of Slink Mobile SDK for Android.
 *
 * @author Shuu Shisen <shuu.shisen@secioss.co.jp>
 * @copyright 2016 SECIOSS, INC.
 * @see http://www.secioss.co.jp
 */
@SuppressWarnings("deprecation")
@TargetApi(Build.VERSION_CODES.LOLLIPOP)
@SuppressLint({"SetJavaScriptEnabled"})
public class SeciossAuthActivity extends Activity {

    public static final String TAG                       = "SeciossAuth";

    public static final String KEY_RESULT                = "SECIOSS_AUTH_RESULT";
    public static final String KEY_SESS                  = "SECIOSS_SESSION_PARAM";
    public static final String KEY_TYPE                  = "SECIOSS_RETURN_TYPE";
    public static final String KEY_FUNC                  = "SECIOSS_FUNCTION";

    public static final String KEY_INIT                  = "SECIOSS_INIT_URL";
    public static final String KEY_BACK                  = "SECIOSS_BACK_URL";
    public static final String KEY_BASE                  = "SECIOSS_BASE_URL";
    public static final String KEY_FAIL                  = "SECIOSS_FAIL_URL";

    public static final String KEY_CLIENTCERT_REQURL     = "SECIOSS_CLIENTCERT_REQURL";
    public static final String KEY_SERVERCERT_FILEPATH   = "SECIOSS_SERVERCERT_FILEPATH";
    public static final String KEY_CLIENTCERT_FILEPATH   = "SECIOSS_CLIENTCERT_FILEPATH";
    public static final String KEY_CLIENTCERT_PASSWORD   = "SECIOSS_CLIENTCERT_PASSWORD";
    public static final String KEY_TRUST_HOSTNAME        = "SECIOSS_TRUST_HOSTNAME";

    public static final String KEY_OAUTH_FINISH          = "SECIOSS_OAUTH2_FINISH";
    public static final String KEY_OAUTH_AUTHORIZE       = "SECIOSS_OAUTH2_AUTHORIZE";
    public static final String KEY_OAUTH_TOKEN           = "SECIOSS_OAUTH2_TOKEN";
    public static final String KEY_OAUTH_RESOURCE        = "SECIOSS_OAUTH2_RESOURCE";
    public static final String KEY_OAUTH_CLIENTID        = "SECIOSS_OAUTH2_CLIENT_ID";
    public static final String KEY_OAUTH_CLIENTSECRET    = "SECIOSS_OAUTH2_CLIENT_SECRET";
    public static final String KEY_OAUTH_REDIRECTURI     = "SECIOSS_OAUTH2_REDIRECT_URI";
    public static final String KEY_OAUTH_SCOPE           = "SECIOSS_OAUTH2_SCOPE";
    public static final String KEY_OAUTH_RESPONSETYPE    = "SECIOSS_OAUTH2_RESPONSE_TYPE";

    public static final String KEY_OIDC_FINISH           = "SECIOSS_OIDC_FINISH";
    public static final String KEY_OIDC_AUTHORIZE        = "SECIOSS_OIDC_AUTHORIZE";
    public static final String KEY_OIDC_TOKEN            = "SECIOSS_OIDC_TOKEN";
    public static final String KEY_OIDC_RESOURCE         = "SECIOSS_OIDC_RESOURCE";
    public static final String KEY_OIDC_CLIENTID         = "SECIOSS_OIDC_CLIENT_ID";
    public static final String KEY_OIDC_CLIENTSECRET     = "SECIOSS_OIDC_CLIENT_SECRET";
    public static final String KEY_OIDC_REDIRECTURI      = "SECIOSS_OIDC_REDIRECT_URI";
    public static final String KEY_OIDC_SCOPE            = "SECIOSS_OIDC_SCOPE";
    public static final String KEY_OIDC_RESPONSETYPE     = "SECIOSS_OIDC_RESPONSE_TYPE";

    public static final String KEY_OIDC_JWKS             = "SECIOSS_OIDC_JWKS";
    public static final String KEY_OIDC_JWKSURI          = "SECIOSS_OIDC_JWKS_URI";
    public static final String KEY_OIDC_MAXAGE           = "SECIOSS_OIDC_MAX_AGE";
    public static final String KEY_OIDC_CLAIMS           = "SECIOSS_OIDC_CLAIMS";
    public static final String KEY_OIDC_ISSUER           = "SECIOSS_OIDC_ISSUER";

    public static final String VAL_FUNC_LOGIN            = "LOGIN";
    public static final String VAL_FUNC_OAUTH            = "OAUTH2";
    public static final String VAL_FUNC_OIDC             = "OIDC";

    public static final String VAL_OAUTH_INITURL         = "file:///android_asset/www/oauth2.html";
    public static final String VAL_OAUTH_AUTHORIZE       = "https://slink.secioss.com/service/oauth/authorize.php";
    public static final String VAL_OAUTH_TOKEN           = "https://slink.secioss.com/service/oauth/token.php";
    public static final String VAL_OAUTH_RESOURCE        = "https://slink.secioss.com/service/oauth/resource.php";
    public static final String VAL_OAUTH_REDIRECTURI     = "seciossauth://www/oauth2.html";
    public static final String VAL_OAUTH_SCOPE           = "profile email";
    public static final String VAL_OAUTH_RESPONSETYPE    = "code";
    public static final String VAL_OAUTH_FINISH          = "USERINFO";
    public static final String VAL_OAUTH_FINISH_TOKEN    = "TOKEN";
    public static final String VAL_OAUTH_FINISH_USERINFO = "USERINFO";

    public static final String VAL_OIDC_INITURL          = "file:///android_asset/www/oidc.html";
    public static final String VAL_OIDC_AUTHORIZE        = "https://slink.secioss.com/oidc/authorize.php";
    public static final String VAL_OIDC_TOKEN            = "https://slink.secioss.com/oidc/token.php";
    public static final String VAL_OIDC_RESOURCE         = "https://slink.secioss.com/oidc/resource.php";
    public static final String VAL_OIDC_REDIRECTURI      = "seciossauth://www/oidc.html";
    public static final String VAL_OIDC_SCOPE            = "openid";
    public static final String VAL_OIDC_RESPONSETYPE     = "id_token token";
    public static final String VAL_OIDC_JWKSURI          = "https://slink.secioss.com/oidc/keys.php";
    public static final String VAL_OIDC_ISSUER           = "https://slink.secioss.com";
    public static final String VAL_OIDC_FINISH           = "CLAIMS";
    public static final String VAL_OIDC_FINISH_TOKEN     = "TOKEN";
    public static final String VAL_OIDC_FINISH_IDTOKEN   = "IDTOKEN";
    public static final String VAL_OIDC_FINISH_CLAIMS    = "CLAIMS";

    public static final String VAL_TYPE_CONTENT          = "RETURN_CONTENT";
    public static final String VAL_TYPE_HEADER           = "RETURN_HEADER";
    public static final String VAL_TYPE_COOKIE           = "RETURN_COOKIE";
    public static final String VAL_TYPE_JSON             = "RETURN_JSON";
    public static final String VAL_TYPE_XML              = "RETURN_XML";
    public static final String VAL_TYPE_HTM              = "RETURN_HTM"; // Meta refresh
    public static final String VAL_TYPE_URL              = "RETURN_URL"; // Location redirect

    public static final String HTML_REDIRECT             = "<html><head><meta http-equiv=\"refresh\" content=\"0;URL={$url}\"/></head></html>";

    public static final int MSG_NORMALDONE               = 0;
    public static final int MSG_CLIENTCERT_HTM           = 1;
    public static final int MSG_CLIENTCERT_URL           = 2;

    private String mFunc;
    private String mInit;
    private String mBack;
    private String mBase;
    private String mFail;
    private String mType;
    private String mSess;
    private String mCertrequrl;
    private String mServercert;
    private String mClientcert;
    private String mClientpass;

    private String mOAuthFinish;
    private String mOAuthAuthorize;
    private String mOAuthToken;
    private String mOAuthResource;
    private String mOAuthClientid;
    private String mOAuthClientsecret;
    private String mOAuthRedirecturi;
    private String mOAuthScope;
    private String mOAuthResponsetype;

    private String mOIDCFinish;
    private String mOIDCAuthorize;
    private String mOIDCToken;
    private String mOIDCResource;
    private String mOIDCClientid;
    private String mOIDCClientsecret;
    private String mOIDCRedirecturi;
    private String mOIDCScope;
    private String mOIDCResponsetype;

    private String mOIDCJwks;
    private String mOIDCJwksuri;
    private String mOIDCMaxage;
    private String mOIDCClaims;
    private String mOIDCIssuer;

    private RelativeLayout mRLayout;
    private WebView mWebView;
    private Handler mHandler;
    private CookieManager mCookieManager;

    private String[] mTrustHostnames;
    private HostnameVerifier mHostnameVerifier;
    private SSLSocketFactory mSSLSocketFactory;

    private PrivateKey mClentcertPrivateKey;
    private X509Certificate[] mX509CertificateChain;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Bundle extras = getIntent().getExtras();
        if (extras == null) {
            Log.e(TAG, "Invalid implementation");
            Toast.makeText(this, "Invalid implementation", Toast.LENGTH_LONG).show();
            setResult(RESULT_CANCELED);
            finish();
        }

        setContentView(R.layout.activity_seciossauth);
        mRLayout = (RelativeLayout) findViewById(R.id.lyt_seciossauth);
        mWebView = (WebView) findViewById(R.id.web_seciossauth);
        mWebView.clearCache(true);
        mWebView.clearHistory();
        mWebView.getSettings().setCacheMode(android.webkit.WebSettings.LOAD_NO_CACHE);
        mWebView.getSettings().setJavaScriptEnabled(true);
        mWebView.getSettings().setDomStorageEnabled(true);
        mWebView.getSettings().setAllowUniversalAccessFromFileURLs(true);
        mWebView.addJavascriptInterface(new SeciossJSInterface(), "SeciossJSI");
        mWebView.setWebChromeClient(new WebChromeClient());
        mWebView.setWebViewClient(new SeciossWebViewClient());

        mCookieManager = CookieManager.getInstance();
        mCookieManager.removeAllCookie();
        if (android.os.Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            mCookieManager.removeAllCookies(null);
        }

        // SAML or 共通
        mFunc                  = extras.getString(KEY_FUNC)                != null ? extras.getString(KEY_FUNC)                : "";
        mInit                  = extras.getString(KEY_INIT)                != null ? extras.getString(KEY_INIT)                : "";
        mBack                  = extras.getString(KEY_BACK)                != null ? extras.getString(KEY_BACK)                : "";
        mBase                  = extras.getString(KEY_BASE)                != null ? extras.getString(KEY_BASE)                : "";
        mFail                  = extras.getString(KEY_FAIL)                != null ? extras.getString(KEY_FAIL)                : "";
        mType                  = extras.getString(KEY_TYPE)                != null ? extras.getString(KEY_TYPE)                : "";
        mSess                  = extras.getString(KEY_SESS)                != null ? extras.getString(KEY_SESS)                : "sessid";
        mCertrequrl            = extras.getString(KEY_CLIENTCERT_REQURL)   != null ? extras.getString(KEY_CLIENTCERT_REQURL)   : "/pub/certlogin.cgi";
        mServercert            = extras.getString(KEY_SERVERCERT_FILEPATH) != null ? extras.getString(KEY_SERVERCERT_FILEPATH) : "";
        mClientcert            = extras.getString(KEY_CLIENTCERT_FILEPATH) != null ? extras.getString(KEY_CLIENTCERT_FILEPATH) : "";
        mClientpass            = extras.getString(KEY_CLIENTCERT_PASSWORD) != null ? extras.getString(KEY_CLIENTCERT_PASSWORD) : "";

        // OAuth 2.0
        if (VAL_FUNC_OAUTH.equalsIgnoreCase(mFunc)) {
            mOAuthFinish       = extras.getString(KEY_OAUTH_FINISH)        != null ? extras.getString(KEY_OAUTH_FINISH)        : VAL_OAUTH_FINISH;
            mOAuthAuthorize    = extras.getString(KEY_OAUTH_AUTHORIZE)     != null ? extras.getString(KEY_OAUTH_AUTHORIZE)     : VAL_OAUTH_AUTHORIZE;
            mOAuthToken        = extras.getString(KEY_OAUTH_TOKEN)         != null ? extras.getString(KEY_OAUTH_TOKEN)         : VAL_OAUTH_TOKEN;
            mOAuthResource     = extras.getString(KEY_OAUTH_RESOURCE)      != null ? extras.getString(KEY_OAUTH_RESOURCE)      : VAL_OAUTH_RESOURCE;
            mOAuthClientid     = extras.getString(KEY_OAUTH_CLIENTID)      != null ? extras.getString(KEY_OAUTH_CLIENTID)      : "";
            mOAuthClientsecret = extras.getString(KEY_OAUTH_CLIENTSECRET)  != null ? extras.getString(KEY_OAUTH_CLIENTSECRET)  : "";
            mOAuthRedirecturi  = extras.getString(KEY_OAUTH_REDIRECTURI)   != null ? extras.getString(KEY_OAUTH_REDIRECTURI)   : VAL_OAUTH_REDIRECTURI;
            mOAuthScope        = extras.getString(KEY_OAUTH_SCOPE)         != null ? extras.getString(KEY_OAUTH_SCOPE)         : VAL_OAUTH_SCOPE;
            mOAuthResponsetype = extras.getString(KEY_OAUTH_RESPONSETYPE)  != null ? extras.getString(KEY_OAUTH_RESPONSETYPE)  : VAL_OAUTH_RESPONSETYPE;
        }
        // OpenID Connect 1.0
        else if (VAL_FUNC_OIDC.equalsIgnoreCase(mFunc)) {
            mOIDCFinish        = extras.getString(KEY_OIDC_FINISH)         != null ? extras.getString(KEY_OIDC_FINISH)         : VAL_OIDC_FINISH;
            mOIDCAuthorize     = extras.getString(KEY_OIDC_AUTHORIZE)      != null ? extras.getString(KEY_OIDC_AUTHORIZE)      : VAL_OIDC_AUTHORIZE;
            mOIDCToken         = extras.getString(KEY_OIDC_TOKEN)          != null ? extras.getString(KEY_OIDC_TOKEN)          : VAL_OIDC_TOKEN;
            mOIDCResource      = extras.getString(KEY_OIDC_RESOURCE)       != null ? extras.getString(KEY_OIDC_RESOURCE)       : VAL_OIDC_RESOURCE;
            mOIDCClientid      = extras.getString(KEY_OIDC_CLIENTID)       != null ? extras.getString(KEY_OIDC_CLIENTID)       : "";
            mOIDCClientsecret  = extras.getString(KEY_OIDC_CLIENTSECRET)   != null ? extras.getString(KEY_OIDC_CLIENTSECRET)   : "";
            mOIDCRedirecturi   = extras.getString(KEY_OIDC_REDIRECTURI)    != null ? extras.getString(KEY_OIDC_REDIRECTURI)    : VAL_OIDC_REDIRECTURI;
            mOIDCScope         = extras.getString(KEY_OIDC_SCOPE)          != null ? extras.getString(KEY_OIDC_SCOPE)          : VAL_OIDC_SCOPE;
            mOIDCResponsetype  = extras.getString(KEY_OIDC_RESPONSETYPE)   != null ? extras.getString(KEY_OIDC_RESPONSETYPE)   : VAL_OIDC_RESPONSETYPE;

            mOIDCJwks          = extras.getString(KEY_OIDC_JWKS)           != null ? extras.getString(KEY_OIDC_JWKS)           : "";
            mOIDCJwksuri       = extras.getString(KEY_OIDC_JWKSURI)        != null ? extras.getString(KEY_OIDC_JWKSURI)        : VAL_OIDC_JWKSURI;
            mOIDCMaxage        = extras.getString(KEY_OIDC_MAXAGE)         != null ? extras.getString(KEY_OIDC_MAXAGE)         : "";
            mOIDCClaims        = extras.getString(KEY_OIDC_CLAIMS)         != null ? extras.getString(KEY_OIDC_CLAIMS)         : "";
            mOIDCIssuer        = extras.getString(KEY_OIDC_ISSUER)         != null ? extras.getString(KEY_OIDC_ISSUER)         : VAL_OIDC_ISSUER;
        }

        if ("".equals(mBack)) {
            if (mInit.indexOf("?") > 0) {
                mBack = mInit.substring(0, mInit.indexOf("?"));
            }
            else {
                mBack = mInit;
            }
        }

        // Trust private hostname
        String trustHostnames = extras.getString(KEY_TRUST_HOSTNAME);
        if (null == trustHostnames || "".equals(trustHostnames)) {
            trustHostnames = "";
            String[] hosts = new String[] {
                    "Init",mInit, "Back",mBack,
                    "OAuth Authorize Endpoint",mOAuthAuthorize, "OAuth Token Endpoint",mOAuthToken, "OAuth Resouce Endpoint",mOAuthResource,
                    "OIDC Authorize Endpoint",mOIDCAuthorize, "OIDC Token Endpoint",mOIDCToken, "OIDC Resouce Endpoint",mOIDCResource
            };
            for (int i = 0; i < hosts.length; i++) {
                try {
                    if (null != hosts[i + 1] && !"".equals(hosts[i + 1])) {
                        trustHostnames += new URL(hosts[i + 1]).getHost() + ",";
                    }
                }
                catch (MalformedURLException e) {
                    Toast.makeText(this, "Invalid " + hosts[i], Toast.LENGTH_LONG).show();
                }
                finally {
                    i++;
                }
            }
        }
        mTrustHostnames = trustHostnames.split(", *");

        // 証明書初期化
        loadCertificates();

        // Handler初期化
        mHandler = new SeciossAuthHandler(this);

        // OAuth 2.0
        if (VAL_FUNC_OAUTH.equalsIgnoreCase(mFunc)) {
            mInit = VAL_OAUTH_INITURL;
            initWebStorage();
        }
        // OpenID Connect 1.0
        else if (VAL_FUNC_OIDC.equalsIgnoreCase(mFunc)) {
            mInit = VAL_OIDC_INITURL;
            initWebStorage();
        }
        else {
            mWebView.loadUrl(mInit);
        }
    }

    /**
     * Initialize WebStorage for WebView
     * This method is designated to be called when using JavaScript
     * to retrieve OAuth or OpenID Connect resources.
     */
    private void initWebStorage() {
        String html = "<html><head><script type=\"text/javascript\">function a() {";
        if (VAL_FUNC_OAUTH.equalsIgnoreCase(mFunc)) {
            html += "sessionStorage.setItem('" + KEY_OAUTH_FINISH       + "', '" + mOAuthFinish + "');";
            html += "sessionStorage.setItem('" + KEY_OAUTH_AUTHORIZE    + "', '" + mOAuthAuthorize + "');";
            html += "sessionStorage.setItem('" + KEY_OAUTH_TOKEN        + "', '" + mOAuthToken + "');";
            html += "sessionStorage.setItem('" + KEY_OAUTH_RESOURCE     + "', '" + mOAuthResource + "');";
            html += "sessionStorage.setItem('" + KEY_OAUTH_CLIENTID     + "', '" + mOAuthClientid + "');";
            html += "sessionStorage.setItem('" + KEY_OAUTH_CLIENTSECRET + "', '" + mOAuthClientsecret + "');";
            html += "sessionStorage.setItem('" + KEY_OAUTH_REDIRECTURI  + "', '" + mOAuthRedirecturi + "');";
            html += "sessionStorage.setItem('" + KEY_OAUTH_SCOPE        + "', '" + mOAuthScope + "');";
            html += "sessionStorage.setItem('" + KEY_OAUTH_RESPONSETYPE + "', '" + mOAuthResponsetype + "');";
        }
        else if (VAL_FUNC_OIDC.equalsIgnoreCase(mFunc)) {
            html += "sessionStorage.setItem('" + KEY_OIDC_FINISH        + "', '" + mOIDCFinish + "');";
            html += "sessionStorage.setItem('" + KEY_OIDC_AUTHORIZE     + "', '" + mOIDCAuthorize + "');";
            html += "sessionStorage.setItem('" + KEY_OIDC_TOKEN         + "', '" + mOIDCToken + "');";
            html += "sessionStorage.setItem('" + KEY_OIDC_RESOURCE      + "', '" + mOIDCResource + "');";
            html += "sessionStorage.setItem('" + KEY_OIDC_CLIENTID      + "', '" + mOIDCClientid + "');";
            html += "sessionStorage.setItem('" + KEY_OIDC_CLIENTSECRET  + "', '" + mOIDCClientsecret + "');";
            html += "sessionStorage.setItem('" + KEY_OIDC_REDIRECTURI   + "', '" + mOIDCRedirecturi + "');";
            html += "sessionStorage.setItem('" + KEY_OIDC_SCOPE         + "', '" + mOIDCScope + "');";
            html += "sessionStorage.setItem('" + KEY_OIDC_RESPONSETYPE  + "', '" + mOIDCResponsetype + "');";
            if (!"".equals(mOIDCJwks)) {
                html += "sessionStorage.setItem('" + KEY_OIDC_JWKS      + "', '" + mOIDCJwks + "');";
            }
            else {
                html += "sessionStorage.setItem('" + KEY_OIDC_JWKSURI   + "', '" + mOIDCJwksuri + "');";
            }
            html += "sessionStorage.setItem('" + KEY_OIDC_MAXAGE        + "', '" + mOIDCMaxage + "');";
            html += "sessionStorage.setItem('" + KEY_OIDC_CLAIMS        + "', '" + mOIDCClaims + "');";
            html += "sessionStorage.setItem('" + KEY_OIDC_ISSUER        + "', '" + mOIDCIssuer + "');";
        }
        html += "window.location='" + mInit + "';}</script></head><body onload=\"a()\"></body></html>";
        mWebView.loadDataWithBaseURL(mInit, html, "text/html", "UTF-8", mInit);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        mHandler.removeCallbacksAndMessages(null);
        mCookieManager.removeAllCookie();
        if (android.os.Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            mCookieManager.removeAllCookies(null);
        }

        mRLayout.removeView(mWebView);
        mWebView.removeAllViews();
        mWebView.destroy();
    }

    @Override
    public boolean onKeyDown(int keyCode, KeyEvent event) {
        if (event.getAction() == KeyEvent.ACTION_DOWN) {
            switch (keyCode) {
                case KeyEvent.KEYCODE_BACK:
                    mWebView.loadUrl("javascript:window.SeciossJSI.processResponse('');");
                    return true;
            }
        }
        return super.onKeyDown(keyCode, event);
    }

    /**
     * When authentication process is finished this method is called to
     * return the authentication result to your application.
     * @param result the result to be returned
     */
    private void doFinishAuth(String result) {
        Intent resultIntent = new Intent();
        resultIntent.putExtra(KEY_RESULT, null != result ? result : "");
        setResult(RESULT_OK, resultIntent);
        finish();
    }

    /**
     * The bridge for JavaScript code to native code
     */
    private class SeciossJSInterface {
        @JavascriptInterface
        public void processResponse(String jsResult) {
            doFinishAuth(jsResult);
        }
    }

    /**
     * Customized WebView Client to handle the authentication process
     */
    private class SeciossWebViewClient extends WebViewClient {

        // LOLLIPOP以降、自動で証明書認証をさせる
        @Override
        public void onReceivedClientCertRequest(WebView view, ClientCertRequest request) {
            if (null != mClentcertPrivateKey && null != mX509CertificateChain && mX509CertificateChain.length > 0) {
                request.proceed(mClentcertPrivateKey, mX509CertificateChain);
            }
            else {
                Toast.makeText(getApplicationContext(), "onReceivedClientCertRequest", Toast.LENGTH_LONG).show();
                request.cancel();
            }
        }

        @Override
        public void onPageStarted(WebView view, String url, Bitmap favicon) {
            super.onPageStarted(view, url, favicon);
        }

        @Override
        public boolean shouldOverrideUrlLoading(final WebView view, final String url) {
            SeciossHttpAsyncTask asyncTask;

            // OAUTH/OIDCのリダイレクトURIを変換する
            if (url.startsWith("seciossauth://www/")) {
                String newUrl = url.replace("seciossauth://", "file:///android_asset/");
                view.loadUrl(newUrl);
                return true;
            }
            // 認証正常完了
            else if (url.startsWith(mBack) && (VAL_TYPE_CONTENT.equalsIgnoreCase(mType) || VAL_TYPE_HEADER.equalsIgnoreCase(mType))) {
                // Use HttpURLConnection for Gingerbread or later, and HTTPClient(not implemented in Secioss MobileSDK) for Froyo and earlier
                // Use HttpURLConnection to retrieve server response which should manager cookies manually before LOLLIPOP
                asyncTask = new SeciossHttpAsyncTask(mHandler, true, mType, mSess, mCookieManager, mHostnameVerifier, mSSLSocketFactory);
                asyncTask.execute(url);
                return true;
            }
            // LOLLIPOP以前、手動で証明書認証させる
            else if (null != mCertrequrl && android.os.Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
                String[] aryCertrequrl = mCertrequrl.split(", *");
                for (int i = 0; i < aryCertrequrl.length; i++) {
                    if (url.contains(aryCertrequrl[i])) {
                        asyncTask = new SeciossHttpAsyncTask(mHandler, false, VAL_TYPE_HTM, mSess, mCookieManager, mHostnameVerifier, mSSLSocketFactory);
                        asyncTask.execute(url);
                        return true;
                    }
                }
            }

            return false;
        }

        @Override
        public void onPageFinished(WebView view, String url) {
            if (url.startsWith(mBack)) {
                if (VAL_TYPE_JSON.equalsIgnoreCase(mType) || VAL_TYPE_XML.equalsIgnoreCase(mType)) {
                    view.loadUrl("javascript:window.SeciossJSI.processResponse(document.documentElement.outerHTML);");
                }
                else if (VAL_TYPE_COOKIE.equalsIgnoreCase(mType)) {
                    String cookies = mCookieManager.getCookie(url);
                    doFinishAuth(cookies);
                }
            }
        }

        @Override
        public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
            String hostname = "";
            try {
                hostname = new URL(error.getUrl()).getHost();
            }
            catch (MalformedURLException e) {
            }

            if (Arrays.asList(mTrustHostnames).contains(hostname)) {
                handler.proceed();
            }
            else {
                super.onReceivedSslError(view, handler, error);
            }
        }

        @Override
        public void onReceivedError(WebView view, int errorCode, String description, String failingUrl) {
            // Deprecate in API level 23
            Log.e(TAG, description + "(" + errorCode + "): " + failingUrl);
            Toast.makeText(getApplicationContext(), description + "(" + errorCode + "): " + failingUrl, Toast.LENGTH_LONG).show();
        }

    }

    /**
     * Handler for parallel process when needed
     */
    private static class SeciossAuthHandler extends Handler {
        WeakReference<SeciossAuthActivity> reference;

        public SeciossAuthHandler(SeciossAuthActivity outer) {
            reference = new WeakReference<SeciossAuthActivity>(outer);
        }

        @Override
        public void handleMessage(Message msg) {
            SeciossAuthActivity outer = reference.get();

            Bundle bundle = msg.getData();
            String data = bundle.getString("data");
            String sessid = bundle.getString("sessid");
            String mimeType = bundle.getString("mimeType");
            String encoding = bundle.getString("encoding");

            switch (msg.what) {
                case MSG_NORMALDONE:
                    outer.doFinishAuth(data);
                    break;
                case MSG_CLIENTCERT_HTM:
                    if ("".equals(outer.mBase)) {
                        outer.mWebView.loadData(data, mimeType, encoding);
                    }
                    else {
                        outer.mWebView.loadDataWithBaseURL(outer.mBase, data, mimeType, encoding, outer.mFail);
                    }
                    break;
                case MSG_CLIENTCERT_URL:
                    if ("".equals(data) && !"".equals(outer.mBase)) {
                        String separator = outer.mBase.contains("?") ? "&" : "?";
                        data = outer.mBase + separator + outer.mSess + "=" + sessid;
                    }
                    String htm = HTML_REDIRECT.replace("{$url}", data);
                    outer.mWebView.loadData(htm, mimeType, encoding);
                    break;
            }
        }
    };

    // =========================================================================
    // =========================================================================

    /**
     * Load all certificates and essentials
     */
    private void loadCertificates() {

        // Hostname Verifier
        mHostnameVerifier = new HostnameVerifier() {
            @Override
            public boolean verify(String hostname, SSLSession session) {
                if (Arrays.asList(mTrustHostnames).contains(hostname)) {
                    return true;
                }
                else {
                    HostnameVerifier verifier = HttpsURLConnection.getDefaultHostnameVerifier();
                    return verifier.verify(hostname, session);
                }
            }
        };

        BufferedInputStream in = null;
        TrustManager[] trustManagers = null;
        KeyManager[] keyManagers = null;
        KeyStore keyStore = null;
        SSLContext sslContext = null;
        boolean keyStoreError = false;

        // Load Server Certificate
        if (!"".equals(mServercert)) {
            String[] aryServerCert = mServercert.split(", *");
            for (int i = 0; i < aryServerCert.length; i++) {
                File servercert = new File(aryServerCert[i]);
                if (servercert.exists()) {
                    try {
                        in = new BufferedInputStream(pem2der(servercert));
                        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                        X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(in);
                        String subject = cert.getSubjectX500Principal().getName();
                        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
                        trustStore.load(null);
                        trustStore.setCertificateEntry(subject, cert);
                        trustManagers = new TrustManager[] {new SeciossTrustManager(trustStore)};
                    }
                    catch (Exception e) {
                        Log.e(TAG, "Load server certificate failed: " + e.toString());
                        Toast.makeText(this, "Load server certificate failed: " + e.toString(), Toast.LENGTH_LONG).show();
                    }
                }
                else {
                    // Toast.makeText(this, "Server certificate not exist", Toast.LENGTH_LONG).show();
                }
            }
        }

        // Load Client Certificate
        if (!"".equals(mClientcert)) {
            File clientcert = new File(mClientcert);
            if (clientcert.exists()) {
                try {
                    in = new BufferedInputStream(new FileInputStream(clientcert));
                    keyStore = KeyStore.getInstance("PKCS12");
                    keyStore.load(in, mClientpass.toCharArray()); // CertificateException
                    KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()); // NoSuchAlgorithmException
                    keyManagerFactory.init(keyStore, mClientpass.toCharArray()); // UnrecoverableKeyException
                    keyManagers = keyManagerFactory.getKeyManagers();
                }
                catch (Exception e) {
                    keyStoreError = true;
                    Log.e(TAG, "Load client certificate failed: " + e.toString());
                    Toast.makeText(this, "Load client certificate failed: " + e.toString(), Toast.LENGTH_LONG).show();
                }
            }
            else {
                Toast.makeText(this, "Client certificate not exist", Toast.LENGTH_LONG).show();
            }
        }

        if (in != null) {
            try {
                in.close();
            }
            catch (IOException e) {
            }
        }

        // Initiate Secure Socket Layer Context
        try {
            sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagers, trustManagers, null);
            mSSLSocketFactory = sslContext.getSocketFactory();
        }
        catch (Exception e) {
        }

        // LOLLIPOP以降、自動で証明書認証をさせる
        // Retrieve PrivateKey and Certificate Chain from Client Certificate KeyStore
        if (null != keyStore && !keyStoreError) {
            try {
                Enumeration<String> aliases = keyStore.aliases();
                while (aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();
                    mClentcertPrivateKey = (PrivateKey) keyStore.getKey(alias, mClientpass.toCharArray());
                    Certificate[] certificateChain = keyStore.getCertificateChain(alias);
                    if (mClentcertPrivateKey != null && certificateChain.length > 0) {
                        mX509CertificateChain = new X509Certificate[certificateChain.length];
                        for (int i = 0; i < certificateChain.length; i++) {
                            mX509CertificateChain[i] = (X509Certificate) certificateChain[i];
                        }
                        break;
                    }
                }
            }
            catch (Exception e) {
                Log.e(TAG, "Retrieve PrivateKey and Certificate Chain from Client Certificate KeyStore failed: " + e.toString());
                Toast.makeText(this, "Retrieve PrivateKey and Certificate Chain from Client Certificate KeyStore failed: " + e.toString(), Toast.LENGTH_LONG).show();
            }
        }

    }

    /**
     * Load a PEM format certificate from file then convert it to DER format
     *
     * @param pemFile the PEM format certificate file
     * @return The DER format InputStream
     * @throws Exception
     */
    private InputStream pem2der(File pemFile) throws Exception {
        boolean isPem = false;
        BufferedInputStream in = null;
        BufferedReader reader = null;

        try {
            in = new BufferedInputStream(new FileInputStream(pemFile));
            reader = new BufferedReader(new InputStreamReader(in));
            StringBuilder buffer = new StringBuilder();
            String line = reader.readLine();
            while (line != null) {
                if (line.equals("-----BEGIN CERTIFICATE-----")) {
                    isPem = true;
                }
                else if (line.equals("-----END CERTIFICATE-----")) {
                    break;
                }
                else if (isPem) {
                    buffer.append(line);
                }
                line = reader.readLine();
            }
            String pemString = buffer.toString();

            byte[] derBytes = Base64.decode(pemString, Base64.DEFAULT);

            return new ByteArrayInputStream(derBytes);
        }
        catch (Exception e) {
            throw e;
        }
        finally {
            if (in != null) {
                try {
                    in.close();
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
        }
    }

}
