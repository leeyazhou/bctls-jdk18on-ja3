/**
 * 
 */
package com.github.leeyazhou.impersonator.util;

import java.util.concurrent.ThreadLocalRandom;

/**
 * 
 * @author leeyazhou
 */
public class GreaseUtil {

  /**
   * Values to account for GREASE (Generate Random Extensions And Sustain Extensibility) as described
   * here: <a href=
   * "https://tools.ietf.org/html/draft-davidben-tls-grease-01">draft-davidben-tls-grease-01</a>.
   */
  private static final int[] GREASE = new int[] {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a,
      0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa};
  
  public static String GREASE_TOKEN = "GREASE";

  public static int randomGrease() {
    return randomGrease(ThreadLocalRandom.current().nextInt(GREASE.length));
  }

  public static int randomGrease(int index) {
    return GREASE[index];
  }

  public static boolean isGrease(int value) {
    for (int grease : GREASE) {
      if (grease == value) {
        return true;
      }
    }
    return false;
  }
}
