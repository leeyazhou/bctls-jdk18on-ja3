package com.github.leeyazhou.impersonator;

import java.io.IOException;
import java.util.Map;

import org.bouncycastle.tls.ClientHello;

/**
 * 
 * 
 * @author leeyazhou
 */
@FunctionalInterface
public interface TlsExtensionListener {

  void onClientExtensionsBuilt(ClientHello clientHello, Map<Integer, byte[]> clientExtensions) throws IOException;

}
