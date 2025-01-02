/**
 * 
 */
package com.github.leeyazhou.impersonator;

import java.util.Map;

/**
 * 
 * @author leeyazhou
 */
public interface TlsExtensionHandler {

  void fillRequestHeaders(Map<String, String> headers);
  
}
