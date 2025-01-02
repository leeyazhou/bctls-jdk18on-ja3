package com.github.leeyazhou.impersonator;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import com.github.leeyazhou.impersonator.http.Http2Connection;

/**
 * 
 * 
 * @author leeyazhou
 */
public interface ImpersonatorFactory {

  SSLContext newSSLContext(KeyManager[] km, TrustManager[] tm);

  // void setExtensionListener(TlsExtensionListener extensionListener);

  /**
   * 4 -> 3 // SETTINGS_MAX_CONCURRENT_STREAMS renumbered.<br/>
   * 7 -> 4 // SETTINGS_INITIAL_WINDOW_SIZE<br/>
   * renumbered.
   */
  void onHttp2ConnectionInit(Http2Connection http2Connection);
}
