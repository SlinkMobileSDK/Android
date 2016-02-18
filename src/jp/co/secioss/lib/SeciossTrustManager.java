package jp.co.secioss.lib;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.CertPathParameters;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import jp.co.secioss.auth.SeciossAuthActivity;
import android.util.Log;

/**
 * This class implements custom TrustManager for trust specific server certificates.
 * It validates the sorted the server certificates in chain order.
 *
 * @author Shuu Shisen <shuu.shisen@secioss.co.jp>
 * @copyright 2016 SECIOSS, INC.
 * @see http://www.secioss.co.jp
 */
public class SeciossTrustManager implements X509TrustManager {

    private final X509TrustManager mX509TrustManager;
    private final KeyStore mTrustStore;

    /**
     * SeciossTrustManager construct method
     * @param trustStore A KeyStore containing the server certificate to be trusted
     */
    public SeciossTrustManager(KeyStore trustStore) throws NoSuchAlgorithmException, KeyStoreException {
        this.mTrustStore = trustStore;

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init((KeyStore) null);

        TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
        mX509TrustManager = (X509TrustManager) trustManagers[0];
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return null;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        return;
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        try {
            mX509TrustManager.checkServerTrusted(chain, authType);
        }
        catch (CertificateException e) {
            try {
                X509Certificate[] newChain = sortChain(chain);
                CertificateFactory factory = CertificateFactory.getInstance("X509");
                CertPath certPath = factory.generateCertPath(Arrays.asList(newChain));

                CertPathParameters params = new PKIXParameters(mTrustStore);

                CertPathValidator validator = CertPathValidator.getInstance("PKIX");
                validator.validate(certPath, params);
            }
            catch (Exception ex) {
                Log.e(SeciossAuthActivity.TAG, ex.toString());
            }
        }
    }

    /**
     * Sort the certificates in chain in singed order.
     * @param chain unsorted chain
     * @return A new chain in singed order.
     */
    private X509Certificate[] sortChain(X509Certificate[] chain) {
        X509Certificate[] newChain = new X509Certificate[chain.length];

        int i = chain.length - 1;
        X509Certificate rootCert = findRootCert(chain);
        newChain[i] = rootCert;

        X509Certificate cert = rootCert;
        while (i > 0 && cert != null) {
            cert = findSignedCert(cert, chain);
            newChain[--i] = cert;
        }

        return newChain;
    }

    /**
     * Find the root cert in certificates chain.
     * @param chain the certificate chain
     * @return the root cert in chain
     */
    private X509Certificate findRootCert(X509Certificate[] chain) {
        for (X509Certificate cert : chain) {
            X509Certificate issuerCert = findIssuerCert(cert, chain);

            // no signer, or self-signed
            if (issuerCert == null || issuerCert.equals(cert)) {
                return cert;
            }
        }

        return null;
    }

    /**
     * Find the issuer of signedCert in the certificates chain.
     * @param signedCert the signed Cert
     * @param chain the certificate chain
     * @return the issuer of signedCert in certificate chain
     */
    private X509Certificate findIssuerCert(X509Certificate signedCert, X509Certificate[] chain) {
        for (X509Certificate cert : chain) {
            // match issuer
            if (cert.getSubjectDN().equals(signedCert.getIssuerDN())) {
                return cert;
            }
        }

        return null;
    }

    /**
     * Find the cert signed by the issuerCert in certificate chain.
     * @param issuerCert the signer Cert
     * @param chain the certificate chain
     * @return the cert signed by issuerCert in certificate chain
     */
    private X509Certificate findSignedCert(X509Certificate issuerCert, X509Certificate[] chain) {
        for (X509Certificate cert : chain) {
            // match issuer also not self-signed
            if (cert.getIssuerDN().equals(issuerCert.getSubjectDN()) && !cert.equals(issuerCert.getSubjectDN())) {
                return cert;
            }
        }

        return null;
    }

}
