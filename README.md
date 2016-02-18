
# Slink Mobile SDK for Android
### 1. Source
###### Java:
    ~/src/jp/co/secioss/auth/SeciossAuthActivity.java
    ~/src/jp/co/secioss/lib/SeciossHttpAsyncTask.java
    ~/src/jp/co/secioss/lib/SeciossTrustManager.java
###### Res:
    ~/res/layout/activity_seciossauth.xml

###### Assets:
    ~/assets/www/jquery.js
    ~/assets/www/jsrsasign.js
    ~/assets/www/oauth2.html
    ~/assets/www/oidc.html
    ~/assets/www/seciossauth.js

### 2. Usage
###### Call SeciossAuth in your project
#### 2.1 Edit the AndroidManifest.xml and add following code:
``` xml
<!-- for permission -->
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />

<!-- for invocation -->
<activity android:name="jp.co.secioss.auth.SeciossAuthActivity" >
    <intent-filter>
        <action android:name="foo.bar.SeciossAuth" />
        <category android:name="android.intent.category.DEFAULT" />
    </intent-filter>
</activity>
```
#### 2.2 Invoke SeciossAuth:
``` java
Intent intent = new Intent("foo.bar.SeciossAuth");
intent.putExtra("name", "value");    // name and value are described below in 4.
startActivityForResult(intent, yourRequestCode);
```
#### 2.3 Retrieve SeciossAuth Result:
``` java
@Override
protected void onActivityResult(int requestCode, int resultCode, Intent intent) {
    // ......
    String result = intent.getStringExtra("SECIOSS_AUTH_RESULT");
}
```

### 3. Notice
1. Use full filepath for server certificates<br>
2. Server certificates can be stored in assets folder<br>
3. There are required parameters for each authentication type.<br>

### 4. Parameters (Same for both iOS and Android)
###### Parameters for each authentication type
#### 4.1 Common
##### 4.1.1 Parameters
    SECIOSS_AUTH_RESULT*          the result of authentication
    SECIOSS_SESSION_PARAM         the parameter of session when session is used
    SECIOSS_FUNCTION*             which authentication (specified below in 4.1.2)
    SECIOSS_TRUST_HOSTNAME        hostname to trust (separated by comma)
    SECIOSS_SERVERCERT_FILEPATH*  the full path of server certificate necessary if self-signed

##### 4.1.2 Values
###### Values of SECIOSS_FUNCTION
    LOGIN                         Use the web based login to authenticate user
    OAUTH2                        Use the OAuth2.0 to authenticate user
    OIDC                          Use the OpenID Connect authenticate user

#### 4.2 Web Based Login
##### 4.2.1 Parameters
    SECIOSS_INIT_URL*             the initialization url
    SECIOSS_BACK_URL*             the redirection url after login success
    SECIOSS_BASE_URL              the direct login url
    SECIOSS_FAIL_URL              the failure url when login page cannot be open
    SECIOSS_RETURN_TYPE           what to return (specified below in 4.2.2)

##### 4.2.2 Values
###### Values of SECIOSS_RETURN_TYPE
    RETURN_CONTENT	              return the response content after success login
    RETURN_HEADER                 return the response http header after success login
    RETURN_COOKIE                 return the any cookie issued after success login
    RETURN_JSON                   return json formate response body after success login
    RETURN_XML                    return xml formate response body after success login

#### 4.3 Certificate Authentication
##### 4.3.1 Parameters
    SECIOSS_CLIENTCERT_REQURL*    the url (snippet) for certificate authentication
    SECIOSS_CLIENTCERT_FILEPATH*  the full path of user certificate file
    SECIOSS_CLIENTCERT_PASSWORD   the password of user certificate

#### 4.4 OAuth2.0
##### 4.4.1 Parameters
    SECIOSS_OAUTH2_FINISH         what to return (specified below in 4.4.2)
    SECIOSS_OAUTH2_AUTHORIZE      OAuth2.0 authorization endpoint url
    SECIOSS_OAUTH2_TOKEN          OAuth2.0 token endpoint url
    SECIOSS_OAUTH2_RESOURCE       OAuth2.0 resource endpoint url
    SECIOSS_OAUTH2_CLIENT_ID      OAuth2.0 client id
    SECIOSS_OAUTH2_CLIENT_SECRET  OAuth2.0 client secret
    SECIOSS_OAUTH2_REDIRECT_URI   OAuth2.0 client redirect uri
    SECIOSS_OAUTH2_SCOPE          OAuth2.0 authorization scope
    SECIOSS_OAUTH2_RESPONSE_TYPE  OAuth2.0 response type in authorization endpoint

##### 4.4.2 Values
###### Values of SECIOSS_OAUTH2_FINISH
    USERINFO                      return user information
    TOKEN                         return access token or refresh token in json string

#### 4.5 OpenID Connect (OIDC)
##### 4.5.1 Parameters
    SECIOSS_OIDC_FINISH           what to return (specified below in 4.4.2)
    SECIOSS_OIDC_AUTHORIZE        OIDC authorization endpoint url
    SECIOSS_OIDC_TOKEN            OIDC token endpoint url
    SECIOSS_OIDC_RESOURCE         OIDC resource endpoint url
    SECIOSS_OIDC_CLIENT_ID        OIDC client id
    SECIOSS_OIDC_CLIENT_SECRET    OIDC client secret
    SECIOSS_OIDC_REDIRECT_URI     OIDC client redirect uri
    SECIOSS_OIDC_SCOPE            OIDC authorization scope
    SECIOSS_OIDC_RESPONSE_TYPE    OIDC response type in authorization endpoint
    SECIOSS_OIDC_JWKS             OIDC JSON web keys
    SECIOSS_OIDC_JWKS_URI         OIDC JSON web keys uri
    SECIOSS_OIDC_CLAIMS           OIDC request claims
    SECIOSS_OIDC_ISSUER           OIDC idtoken issuer to trust (verify)

##### 4.5.2 Values
###### Values of SECIOSS_OIDC_FINISH
    CLAIMS                        return OIDC claims (user information)
    TOKEN                         return access token or refresh token in json string
    IDTOKEN                       return id token

### 5. Samples
###### Samples for each authentication type
#### 5.1 ID/PW Authentication
``` Java
Intent intent = new Intent("foo.bar.SeciossAuth");
intent.putExtra("SECIOSS_FUNCTION", "LOGIN");
intent.putExtra("SECIOSS_INIT_URL", "https://slink.secioss.com/user/");
intent.putExtra("SECIOSS_BACK_URL", "https://slink.secioss.com/user/index.php");
intent.putExtra("SECIOSS_RETURN_TYPE", "RETURN_COOKIE");
startActivityForResult(intent, 0);
```

#### 5.2 Client Certificate Authentication
``` Java
Intent intent = new Intent("foo.bar.SeciossAuth");
intent.putExtra("SECIOSS_FUNCTION", "LOGIN");
intent.putExtra("SECIOSS_INIT_URL", "https://slink.secioss.com/user/");
intent.putExtra("SECIOSS_BACK_URL", "https://slink.secioss.com/user/index.php");
intent.putExtra("SECIOSS_RETURN_TYPE", "RETURN_COOKIE");
intent.putExtra("SECIOSS_CLIENTCERT_REQURL", "https://slink-cert.secioss.com/");
intent.putExtra("SECIOSS_CLIENTCERT_FILEPATH", "/storage/emulated/0/Download/user01.p12");
intent.putExtra("SECIOSS_CLIENTCERT_PASSWORD", "password");
startActivityForResult(intent, 0);
```

#### 5.3 OAuth 2.0 Authorization
``` Java
Intent intent = new Intent("foo.bar.SeciossAuth");
intent.putExtra("SECIOSS_FUNCTION", "OAUTH2");
intent.putExtra("SECIOSS_OAUTH2_AUTHORIZE", "https://slink.secioss.com/service/oauth/authorize.php");
intent.putExtra("SECIOSS_OAUTH2_TOKEN", "https://slink.secioss.com/service/oauth/token.php");
intent.putExtra("SECIOSS_OAUTH2_RESOURCE", "https://slink.secioss.com/service/oauth/resource.php");
intent.putExtra("SECIOSS_OAUTH2_CLIENT_ID", "28x426fK8e249Cz8WaBHGrQHvBxrLn5t");
intent.putExtra("SECIOSS_OAUTH2_CLIENT_SECRET", "secret");
intent.putExtra("SECIOSS_OAUTH2_REDIRECT_URI", "seciossauth://www/oauth2.html");
startActivityForResult(intent, 1);
```

