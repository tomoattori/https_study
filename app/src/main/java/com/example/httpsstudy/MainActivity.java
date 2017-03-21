package com.example.httpsstudy;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import android.view.View;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.Socket;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

@SuppressLint("NewApi")
public class MainActivity extends Activity {
    private final String TAG = "HttpsStudy";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        findViewById(R.id.button).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                ConnectThread connectThread = new ConnectThread();
                connectThread.start();
            }
        });
    }

    // 独自TrustManagerセット済みSSLContextの生成
    private SSLSocketFactory createSSLSocketFactory() {
        try {
            // SSLContext生成
            SSLContext sslContext = SSLContext.getInstance("TLS");

            // 独自TrustManagerの生成
            TrustManager trustManager;
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
                trustManager = createCustomX509TrustManager();
            } else {
                trustManager = createCustomX509ExtendedTrustManager();
            }
            if (trustManager == null) {
                // 生成に失敗したら諦める(通常起こらない)
                return null;
            }

            // 独自TrustManagerをSSLContextにセットして返却
            sslContext.init(null, new TrustManager[] {trustManager}, new SecureRandom());
            return sslContext.getSocketFactory();

        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            // SSLContext周りの処理で失敗したら諦める(通常起こらない)
            return null;
        }
    }

    // 独自TrustManagerの生成
    private X509TrustManager createCustomX509TrustManager() {
        // デフォルトのX509TrustManagerを取得
        final X509TrustManager defaultTrustManager = getDefaultX509TrustManager();
        if (defaultTrustManager == null) {
            // 取得できなかったら諦める(通常起こらない)
            return null;
        }

        // 独自TrustManagerを生成して返却
        return new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
                // デフォルトでのチェックを実施しないと危険(GooglePlayに怒られるし)
                defaultTrustManager.checkClientTrusted(x509Certificates, s);
            }

            @Override
            public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
                // デフォルトでのチェックを実施しないと危険(GooglePlayに怒られるし)
                defaultTrustManager.checkServerTrusted(x509Certificates, s);

                // ここで独自処理を実行(ここでは証明書のsubjectDNをログ出力するだけ
                Log.d(TAG, "SubjectDN : " + x509Certificates[0].getSubjectX500Principal().getName());
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                // ここは使わなければどうでもいいのだけれども
                return defaultTrustManager.getAcceptedIssuers();
            }
        };
    }

    // デフォルトX509TrustManagerの取得
    private X509TrustManager getDefaultX509TrustManager() {
        TrustManagerFactory trustManagerFactory;

        // 標準のTrustManagerを取得
        try {
            trustManagerFactory = TrustManagerFactory
                    .getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init((KeyStore) null);
        } catch (NoSuchAlgorithmException | KeyStoreException e) {
            // TrustManagerが取得できなかったら諦める(通常起こらない)
            return null;
        }
        TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();

        // 取得したTrustManagerからX509TrustManagerを検索
        for (TrustManager trustManager : trustManagers) {
            if (trustManager instanceof X509TrustManager) {
                return (X509TrustManager) trustManager;
            }
        }

        // X509TrustManagerが見つからなかったら諦める(通常起こらない)
        return null;
    }

    // 独自TrustManagerの生成
    private javax.net.ssl.X509ExtendedTrustManager createCustomX509ExtendedTrustManager() {
        // デフォルトのX509TrustManagerを取得
        final javax.net.ssl.X509ExtendedTrustManager defaultTrustManager = getDefaultX509ExtendedTrustManager();
        if (defaultTrustManager == null) {
            // 取得できなかったら諦める(通常起こらない)
            return null;
        }

        // 独自TrustManagerを生成して返却
        return new javax.net.ssl.X509ExtendedTrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
                // HttpsURLConnectionでは使われないっぽいが念のためデフォルトでのチェックを実施
                defaultTrustManager.checkClientTrusted(x509Certificates, s);
            }

            @Override
            public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
                // HttpsURLConnectionでは使われないっぽいが念のためデフォルトでのチェックを実施
                defaultTrustManager.checkServerTrusted(x509Certificates, s);
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                // ここは使わなければどうでもいいのだけれども
                return defaultTrustManager.getAcceptedIssuers();
            }

            @Override
            public void checkClientTrusted(X509Certificate[] x509Certificates, String s, Socket socket) throws CertificateException {
                // デフォルトでのチェックを実施しないと危険(GooglePlayに怒られるし)
                defaultTrustManager.checkClientTrusted(x509Certificates, s, socket);
            }

            @Override
            public void checkServerTrusted(X509Certificate[] x509Certificates, String s, Socket socket) throws CertificateException {
                // デフォルトでのチェックを実施しないと危険(GooglePlayに怒られるし)
                defaultTrustManager.checkServerTrusted(x509Certificates, s, socket);

                // ここで独自処理を実行(ここでは証明書のsubjectDNをログ出力するだけ
                Log.d(TAG, "SubjectDN : " + x509Certificates[0].getSubjectX500Principal().getName());
            }

            @Override
            public void checkClientTrusted(X509Certificate[] x509Certificates, String s, SSLEngine sslEngine) throws CertificateException {
                // HttpsURLConnectionでは使われないっぽいが念のためデフォルトでのチェックを実施
                defaultTrustManager.checkClientTrusted(x509Certificates, s, sslEngine);
            }

            @Override
            public void checkServerTrusted(X509Certificate[] x509Certificates, String s, SSLEngine sslEngine) throws CertificateException {
                // HttpsURLConnectionでは使われないっぽいが念のためデフォルトでのチェックを実施
                defaultTrustManager.checkServerTrusted(x509Certificates, s, sslEngine);
            }
        };

    }

    // デフォルトX509ExtendedTrustManagerの取得
    private javax.net.ssl.X509ExtendedTrustManager getDefaultX509ExtendedTrustManager() {
        TrustManagerFactory trustManagerFactory;

        // 標準のTrustManagerを取得
        try {
            trustManagerFactory = TrustManagerFactory
                    .getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init((KeyStore) null);
        } catch (NoSuchAlgorithmException | KeyStoreException e) {
            // TrustManagerが取得できなかったら諦める(通常起こらない)
            return null;
        }
        TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();

        // 取得したTrustManagerからX509ExtendedTrustManagerを検索
        for (TrustManager trustManager : trustManagers) {
            if (trustManager instanceof X509TrustManager) {
                return (javax.net.ssl.X509ExtendedTrustManager) trustManager;
            }
        }

        // X509ExtendedTrustManagerが見つからなかったら諦める(通常起こらない)
        return null;
    }

    class ConnectThread extends Thread {
        public ConnectThread() {
        }

        public void run() {
            HttpsURLConnection connection = null;
            try {
                URL url = new URL("https://example.com");
                connection = (HttpsURLConnection) url.openConnection();

                // 独自TrustManagerセット済みSSLContextのセット
                SSLSocketFactory sslSocketFactory = createSSLSocketFactory();
                if (sslSocketFactory != null) {
                    connection.setSSLSocketFactory(sslSocketFactory);
                }

                // 接続
                connection.connect();

            } catch (MalformedURLException e) {
                Log.d(TAG, "MalformedURLException : " + e.getMessage());
            } catch (IOException e) {
                Log.d(TAG, "IOException : " + e.getMessage());
            } finally {
                if (connection != null) {
                    connection.disconnect();
                }
            }
        }
    }
}
