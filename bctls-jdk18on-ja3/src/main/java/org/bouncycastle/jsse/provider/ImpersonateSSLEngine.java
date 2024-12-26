package org.bouncycastle.jsse.provider;

import org.bouncycastle.tls.TlsClientProtocol;

import com.github.leeyazhou.impersonator.Impersonator;

class ImpersonateSSLEngine extends ProvSSLEngine {

    private final Impersonator impersonator;

    ImpersonateSSLEngine(ContextData contextData, String peerHost, int peerPort, Impersonator impersonator) {
        super(contextData, peerHost, peerPort);
        this.impersonator = impersonator;
    }

    @Override
    protected TlsClientProtocol newTlsClientProtocol() {
        return new ImpersonateTlsClientProtocol(impersonator);
    }

    @Override
    protected ProvTlsClient newProvTlsClient(ProvSSLParameters sslParameters) {
        int[] cipherSuites = impersonator.getCipherSuites();
        ImpersonateSSLSocketWrap.checkCipherSuites(contextData, cipherSuites);
        return new ImpersonateTlsClient(this, sslParameters, cipherSuites);
    }
}
