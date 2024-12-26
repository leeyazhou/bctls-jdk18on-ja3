package com.github.leeyazhou.impersonator;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

public interface ImpersonatorApi {

	SSLContext newSSLContext(KeyManager[] km, TrustManager[] tm);

	void setExtensionListener(TlsExtensionListener extensionListener);

}
