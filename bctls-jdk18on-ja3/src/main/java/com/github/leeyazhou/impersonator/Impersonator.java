package com.github.leeyazhou.impersonator;

import java.io.IOException;
import java.util.Map;
import org.bouncycastle.tls.ClientHello;

public interface Impersonator {

  int[] getCipherSuites();

  void onEstablishSession(Map<Integer, byte[]> clientExtensions) throws IOException;

  void onSendClientHelloMessage(ClientHello clientHello, Map<Integer, byte[]> clientExtensions) throws IOException;

}
