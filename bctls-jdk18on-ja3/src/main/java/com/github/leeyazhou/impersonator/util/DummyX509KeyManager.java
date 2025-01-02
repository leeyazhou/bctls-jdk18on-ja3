package com.github.leeyazhou.impersonator.util;

import java.security.cert.X509Certificate;
import javax.net.ssl.X509TrustManager;

/**
 * 
 * @author leeyazhou
 */
public class DummyX509KeyManager implements X509TrustManager {
  @Override
  public void checkClientTrusted(X509Certificate[] chain, String authType) {}

  @Override
  public void checkServerTrusted(X509Certificate[] chain, String authType) {}

  @Override
  public X509Certificate[] getAcceptedIssuers() {
    return new X509Certificate[0];
  }
}
