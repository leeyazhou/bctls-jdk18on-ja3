/**
 * 
 */
package com.github.leeyazhou.impersonator.util;

import ja3.okhttp3.Http2Connection;
import ja3.okhttp3.Settings;

/**
 * 
 * @author leeyazhou
 */
public class HttpConnectionUtil {
  
  public static void configChromeHttp2Settings(Http2Connection http2Connection) {
    http2Connection.removeSetting(Settings.INITIAL_WINDOW_SIZE);
    http2Connection.setSetting(Settings.HEADER_TABLE_SIZE, 65536);
    http2Connection.setSetting(Settings.ENABLE_PUSH, 0);
    http2Connection.setSetting(Settings.INITIAL_WINDOW_SIZE, 6291456);
    http2Connection.setSetting(Settings.MAX_HEADER_LIST_SIZE, 262144);
    http2Connection.setWindowSizeIncrement(15663105L);
    http2Connection.setHeaderOrder("m,a,s,p");
  }
  
}
