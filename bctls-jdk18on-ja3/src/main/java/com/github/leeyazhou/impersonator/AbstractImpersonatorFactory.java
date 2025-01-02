package com.github.leeyazhou.impersonator;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.tls.ClientHello;
import org.bouncycastle.tls.ExtensionType;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsExtensionsUtils;
import org.bouncycastle.tls.TlsUtils;
import com.github.leeyazhou.impersonator.terminal.Android;
import com.github.leeyazhou.impersonator.terminal.MacChrome;
import com.github.leeyazhou.impersonator.terminal.MacFirefox129;
import com.github.leeyazhou.impersonator.terminal.MacSafari;
import com.github.leeyazhou.impersonator.util.DummyX509KeyManager;
import com.github.leeyazhou.impersonator.util.GreaseUtil;

/**
 * 
 * 
 * @author leeyazhou
 */
public abstract class AbstractImpersonatorFactory implements ImpersonatorFactory, Impersonator, TlsExtensionHandler {

  static {
    Security.addProvider(new BouncyCastleProvider());
    Security.addProvider(new BouncyCastleJsseProvider());
  }

  public static ImpersonatorFactory macChrome() {
    return new MacChrome();
  }

  public static ImpersonatorFactory macSafari() {
    return MacSafari.newMacSafari();
  }

  public static ImpersonatorFactory macFirefox() {
    return new MacFirefox129();
  }

  public static ImpersonatorFactory ios() {
    return MacSafari.newIOS();
  }

  public static ImpersonatorFactory android() {
    return new Android();
  }

  private final int[] cipherSuites;

  protected AbstractImpersonatorFactory(String cipherSuites) {
    String[] tokens = cipherSuites.split("-");
    this.cipherSuites = new int[tokens.length];
    for (int i = 0; i < tokens.length; i++) {
      String token = tokens[i];
      if (GreaseUtil.GREASE_TOKEN.equalsIgnoreCase(token)) {
        this.cipherSuites[i] = GreaseUtil.randomGrease();
      } else {
        int cipherSuite = Integer.parseInt(token);
        this.cipherSuites[i] = cipherSuite;
      }
    }
  }

  @Override
  public SSLContext newSSLContext(KeyManager[] km, TrustManager[] tm) {
    try {
      if (tm == null || tm.length == 0) {
        tm = new TrustManager[] {new DummyX509KeyManager()};
      }
      // BouncyCastleJsseProvider provider = new BouncyCastleJsseProvider();
      // provider.configure(userAgent);
      SSLContext context = SSLContext.getInstance("TLSv1.3", BouncyCastleJsseProvider.PROVIDER_NAME);
      context.init(km, tm, new SecureRandomWrap(this));
      return context;
    } catch (NoSuchAlgorithmException | NoSuchProviderException | KeyManagementException e) {
      throw new IllegalStateException("newContext", e);
    }
  }

  protected final void addSignatureAlgorithmsExtension(Map<Integer, byte[]> clientExtensions,
      SignatureAndHashAlgorithm... signatureAndHashAlgorithms) throws IOException {
    Vector<SignatureAndHashAlgorithm> supportedSignatureAlgorithms = new Vector<>(signatureAndHashAlgorithms.length);
    supportedSignatureAlgorithms.addAll(Arrays.asList(signatureAndHashAlgorithms));
    TlsExtensionsUtils.addSignatureAlgorithmsExtension(clientExtensions, supportedSignatureAlgorithms);
  }

  protected final void addDelegatedCredentialsExtension(Map<Integer, byte[]> clientExtensions,
      SignatureAndHashAlgorithm... signatureAndHashAlgorithms) throws IOException {
    Vector<SignatureAndHashAlgorithm> supportedSignatureAlgorithms = new Vector<>(signatureAndHashAlgorithms.length);
    supportedSignatureAlgorithms.addAll(Arrays.asList(signatureAndHashAlgorithms));
    TlsExtensionsUtils.addDelegatedCredentialsExtension(clientExtensions, supportedSignatureAlgorithms);
  }

  protected final void addSupportedGroupsExtension(Map<Integer, byte[]> clientExtensions, Integer... groups)
      throws IOException {
    Vector<Integer> supportedGroups = new Vector<>();
    Collections.addAll(supportedGroups, groups);
    TlsExtensionsUtils.addSupportedGroupsExtension(clientExtensions, supportedGroups);
  }

  protected final void randomSupportedVersionsExtension(Map<Integer, byte[]> clientExtensions,
      ProtocolVersion... protocolVersions) throws IOException {
    List<ProtocolVersion> list = new ArrayList<>(protocolVersions.length + 1);
    // int grease = randomGrease(14);
    int grease = GreaseUtil.randomGrease();
    list.add(ProtocolVersion.get(grease >> 8, grease & 0xff));
    Collections.addAll(list, protocolVersions);
    TlsExtensionsUtils.addSupportedVersionsExtensionClient(clientExtensions, list.toArray(new ProtocolVersion[0]));
  }

  protected static void randomExtension(Map<Integer, byte[]> clientExtensions, String order, boolean needGrease) {
    // byte[] lastGreaseData = needGrease ? TlsUtils.EMPTY_BYTES : null;
    byte[] lastGreaseData = needGrease ? new byte[1] : null;
    randomExtension(clientExtensions, order, needGrease ? TlsUtils.EMPTY_BYTES : null, lastGreaseData);
  }

  protected static void randomExtension(Map<Integer, byte[]> clientExtensions, String order, byte[] firstGreaseData,
      byte[] lastGreaseData) {
    Map<Integer, byte[]> copy = new HashMap<>(clientExtensions);
    clientExtensions.clear();
    int grease = GreaseUtil.randomGrease();
    if (firstGreaseData != null) {
      clientExtensions.put(grease, firstGreaseData);
    }
    if (order == null) {
      List<Integer> keys = new ArrayList<>(copy.keySet());
      Collections.shuffle(keys);
      for (Integer key : keys) {
        byte[] data = copy.remove(key);
        clientExtensions.put(key, data);
      }
    } else {
      sortExtensions(clientExtensions, copy, order);
    }
    if (lastGreaseData != null) {
      while (true) {
        int random = GreaseUtil.randomGrease();
        if (random != grease) {
          clientExtensions.put(random, lastGreaseData);
          break;
        }
      }
    }
  }

  protected static void sortExtensions(Map<Integer, byte[]> clientExtensions, Map<Integer, byte[]> copy, String order) {
    if (copy == null) {
      copy = new HashMap<>(clientExtensions);
      clientExtensions.clear();
    }
    String[] tokens = order.split("-");
    for (String token : tokens) {
      int type = Integer.parseInt(token);
      byte[] data = copy.remove(type);
      if (data != null) {
        clientExtensions.put(type, data);
      }
    }
  }

  @Override
  public void onEstablishSession(Map<Integer, byte[]> clientExtensions) throws IOException {
    clientExtensions.put(ExtensionType.renegotiation_info, TlsUtils.encodeOpaque8(TlsUtils.EMPTY_BYTES));
  }

  public static int calcClientHelloMessageLength(ClientHello clientHello) {
    try (ByteArrayOutputStream message = new ByteArrayOutputStream(512)) {
      clientHello.encode(null, message);
      return message.size() + 4;
    } catch (IOException e) {
      throw new IllegalStateException("calcClientHelloMessageLength", e);
    }
  }

  @Override
  public final void onSendClientHelloMessage(ClientHello clientHello, Map<Integer, byte[]> clientExtensions)
      throws IOException {
    clientExtensions.remove(ExtensionType.status_request_v2);
    clientExtensions.remove(ExtensionType.encrypt_then_mac);
    onSendClientHelloMessageInternal(clientExtensions);
    onClientExtensionsBuilt(clientHello, clientExtensions);
  }


  protected abstract void onSendClientHelloMessageInternal(Map<Integer, byte[]> clientExtensions) throws IOException;


  @Override
  public int[] getCipherSuites() {
    return cipherSuites;
  }



}
