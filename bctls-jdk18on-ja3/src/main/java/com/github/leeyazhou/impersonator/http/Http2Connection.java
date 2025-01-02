/**
 * 
 */
package com.github.leeyazhou.impersonator.http;

/**
 * 
 * @author leeyazhou
 */
public interface Http2Connection {


  default void removeSetting(int id) {
      this.setSetting(id, -1);
  }

  void setSetting(int var1, int var2);

  void setWindowSizeIncrement(long var1);

  void setHeaderOrder(String var1);

  void addPriorityFrame(PriorityFrame var1);

}
