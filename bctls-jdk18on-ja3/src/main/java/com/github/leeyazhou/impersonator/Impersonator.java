package com.github.leeyazhou.impersonator;

import java.io.IOException;
import java.util.Map;
import org.bouncycastle.tls.ClientHello;

public interface Impersonator {

  int[] getCipherSuites();
  
  int[] getKeyShareGroups();

  void onEstablishSession(Map<Integer, byte[]> clientExtensions) throws IOException;

  ExtensionOrder onSendClientHelloMessage(ClientHello clientHello, Map<Integer, byte[]> clientExtensions) throws IOException;

}
