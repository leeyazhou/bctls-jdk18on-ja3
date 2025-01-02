package com.github.leeyazhou.impersonator.terminal;

import java.io.IOException;
import java.util.Locale;
import java.util.Map;
import java.util.Vector;
import org.bouncycastle.tls.CertificateCompressionAlgorithm;
import org.bouncycastle.tls.ExtensionType;
import org.bouncycastle.tls.KeyShareEntry;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.PskKeyExchangeMode;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.TlsExtensionsUtils;
import org.bouncycastle.tls.TlsUtils;
import com.github.leeyazhou.impersonator.AbstractImpersonatorFactory;
import com.github.leeyazhou.impersonator.ImpersonatorFactory;
import com.github.leeyazhou.impersonator.TlsExtensionHandler;
import com.github.leeyazhou.impersonator.util.GreaseUtil;
import ja3.okhttp3.Http2Connection;
import ja3.okhttp3.Settings;

/**
 * v17.5 (18618.2.12.111.5, 18618)
 */
public class MacSafari extends AbstractImpersonatorFactory implements TlsExtensionHandler {

  private enum Type {
    MacSafari,

    iOS
  }

  public static ImpersonatorFactory newMacSafari() {
    return new MacSafari(Type.MacSafari);
  }

  public static ImpersonatorFactory newIOS() {
    return new MacSafari(Type.iOS);
  }

  private final Type type;

  private MacSafari(Type type) {
    super(
        "GREASE-4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10");
    this.type = type;
  }

  @Override
  public void fillRequestHeaders(Map<String, String> headers) {
    Locale locale = Locale.getDefault();
    headers.put("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
    headers.put("Accept-Language",
        String.format("%s,%s;q=0.5", locale.toString().replace('_', '-'), locale.getLanguage()));
    headers.put("Sec-Fetch-Dest", "document");
    headers.put("Sec-Fetch-Mode", "navigate");
    headers.put("Sec-Fetch-Site", "none");
  }

  @Override
  public void onHttp2ConnectionInit(Http2Connection http2Connection) {
    http2Connection.removeSetting(Settings.INITIAL_WINDOW_SIZE);
    switch (type) {
      case MacSafari: {
        http2Connection.setSetting(Settings.INITIAL_WINDOW_SIZE, 4194304);
        http2Connection.setSetting(Settings.MAX_CONCURRENT_STREAMS, 100);
        http2Connection.setWindowSizeIncrement(10485760L);
        http2Connection.setHeaderOrder("m,s,p,a");
        break;
      }
      case iOS: {
        http2Connection.setSetting(Settings.ENABLE_PUSH, 0);
        http2Connection.setSetting(Settings.INITIAL_WINDOW_SIZE, 2097152);
        http2Connection.setSetting(Settings.MAX_CONCURRENT_STREAMS, 100);
        http2Connection.setWindowSizeIncrement(10485760L);
        http2Connection.setHeaderOrder("m,s,p,a");
        break;
      }
      default:
        throw new IllegalStateException("Unsupported type: " + type);
    }
  }

  @Override
  protected void onSendClientHelloMessageInternal(Map<Integer, byte[]> clientExtensions) throws IOException {
    clientExtensions.put(ExtensionType.signed_certificate_timestamp, TlsUtils.EMPTY_BYTES);
    addSignatureAlgorithmsExtension(clientExtensions,
        SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_secp256r1_sha256),
        SignatureAndHashAlgorithm.rsa_pss_rsae_sha256,
        SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha256),
        SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_secp384r1_sha384),
        SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_sha1), //
        SignatureAndHashAlgorithm.rsa_pss_rsae_sha384, //
        SignatureAndHashAlgorithm.rsa_pss_rsae_sha384, //
        SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha384),
        SignatureAndHashAlgorithm.rsa_pss_rsae_sha512,
        SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha512),
        SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha1));
    int supportedGroupGrease = GreaseUtil.randomGrease();
    addSupportedGroupsExtension(clientExtensions, supportedGroupGrease, NamedGroup.x25519, NamedGroup.secp256r1,
        NamedGroup.secp384r1, NamedGroup.secp521r1);
    randomSupportedVersionsExtension(clientExtensions, ProtocolVersion.TLSv13, ProtocolVersion.TLSv12,
        ProtocolVersion.TLSv11, ProtocolVersion.TLSv10);
    Vector<KeyShareEntry> keyShareEntries = TlsExtensionsUtils.getKeyShareClientHello(clientExtensions);
    if (keyShareEntries != null) {
      keyShareEntries.add(0, new KeyShareEntry(supportedGroupGrease, new byte[1]));
      TlsExtensionsUtils.addKeyShareClientHello(clientExtensions, keyShareEntries);
    }
    TlsExtensionsUtils.addPaddingExtension(clientExtensions, 0);
    TlsExtensionsUtils.addCompressCertificateExtension(clientExtensions,
        new int[] {CertificateCompressionAlgorithm.zlib});
    TlsExtensionsUtils.addPSKKeyExchangeModesExtension(clientExtensions, new short[] {PskKeyExchangeMode.psk_dhe_ke});
    randomExtension(clientExtensions, "0-23-65281-10-11-16-5-13-18-51-45-43-27-21", true);
  }

}
