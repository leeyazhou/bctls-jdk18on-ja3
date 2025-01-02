/**
 * 
 */
package com.github.leeyazhou.impersonator;

import java.io.IOException;
import java.util.Map;
import org.bouncycastle.tls.ClientHello;

/**
 * 
 * @author leeyazhou
 */
public interface TlsExtensionHandler {

  void fillRequestHeaders(Map<String, String> headers);

  default void onClientExtensionsBuilt(ClientHello clientHello, Map<Integer, byte[]> clientExtensions)
      throws IOException {}
}
