package org.bouncycastle.jsse.provider;

import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsSession;

import com.github.leeyazhou.impersonator.Impersonator;

import java.io.IOException;

class ImpersonateTlsClientProtocol extends TlsClientProtocol {

    private final Impersonator impersonator;

    ImpersonateTlsClientProtocol(Impersonator impersonator) {
        this.impersonator = impersonator;
    }

    @Override
    protected boolean establishSession(TlsSession sessionToResume) {
        try {
            impersonator.onEstablishSession(clientExtensions);
        } catch (IOException e) {
            throw new IllegalStateException("establishSession", e);
        }
        return super.establishSession(sessionToResume);
    }

    @Override
    protected void sendClientHelloMessage() throws IOException {
        try {
            impersonator.onSendClientHelloMessage(clientHello, clientExtensions);
        } catch (IOException e) {
            throw new IllegalStateException("sendClientHelloMessage", e);
        }
        super.sendClientHelloMessage();
    }
}
