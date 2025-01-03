package com.github.leeyazhou.impersonator.terminal;

import java.io.ByteArrayOutputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Map;
import java.util.Vector;
import org.bouncycastle.tls.CertificateCompressionAlgorithm;
import org.bouncycastle.tls.ExtensionType;
import org.bouncycastle.tls.KeyShareEntry;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.OfferedPsks;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.PskIdentity;
import org.bouncycastle.tls.PskKeyExchangeMode;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.TlsExtensionsUtils;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.util.encoders.Hex;
import com.github.leeyazhou.impersonator.AbstractImpersonatorFactory;
import com.github.leeyazhou.impersonator.TlsExtensionHandler;
import com.github.leeyazhou.impersonator.http.Http2Connection;
import com.github.leeyazhou.impersonator.util.GreaseUtil;
import com.github.leeyazhou.impersonator.util.HttpConnectionUtil;

/**
 * v127.0.6533.120
 */
public class MacChrome extends AbstractImpersonatorFactory implements TlsExtensionHandler {

  public MacChrome() {
    super("GREASE-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53");
  }

  @Override
  public void fillRequestHeaders(Map<String, String> headers) {
    // Locale locale = Locale.getDefault();
    // headers.put("Accept",
    // "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7");
    // headers.put("Accept-Language",
    // String.format("%s,%s;q=0.5", locale.toString().replace('_', '-'), locale.getLanguage()));
    // headers.put("Cache-Control", "max-age=0");
    // headers.put("Cookie", "");
    // headers.put("Sec-Ch-Ua", "\"Not)A;Brand\";v=\"99\", \"Google Chrome\";v=\"127\",
    // \"Chromium\";v=\"127\"");
    // headers.put("Sec-Ch-Ua-Mobile", "?0");
    // headers.put("Sec-Ch-Ua-Platform", "\"macOS\"");
    // headers.put("Sec-Fetch-Dest", "document");
    // headers.put("Sec-Fetch-Mode", "navigate");
    // headers.put("Sec-Fetch-Site", "none");
    // headers.put("Sec-Fetch-User", "?1");
    // headers.put("Upgrade-Insecure-Requests", "1");
  }

  @Override
  public void onHttp2ConnectionInit(Http2Connection http2Connection) {
    HttpConnectionUtil.configChromeHttp2Settings(http2Connection);
  }

  static void addApplicationSettingsExtension(Map<Integer, byte[]> clientExtensions) throws IOException {
    try (ByteArrayOutputStream baos = new ByteArrayOutputStream(16)) {
      DataOutput dataOutput = new DataOutputStream(baos);
      dataOutput.writeShort(3);
      byte[] bytes = "h2".getBytes();
      dataOutput.writeByte(bytes.length);
      dataOutput.write(bytes);
      clientExtensions.put(ExtensionType.application_settings, baos.toByteArray());
    }
  }

  @Override
  protected void onSendClientHelloMessageInternal(Map<Integer, byte[]> clientExtensions) throws IOException {
    clientExtensions.put(ExtensionType.signed_certificate_timestamp, TlsUtils.EMPTY_BYTES);
    clientExtensions.put(ExtensionType.session_ticket, TlsUtils.EMPTY_BYTES);
    randomSupportedVersionsExtension(clientExtensions, ProtocolVersion.TLSv13, ProtocolVersion.TLSv12);
    // final int X25519Kyber768Draft00 = 0x6399;
    final int X25519MLKEM768 = 4588;
    // final int supportedGroupGrease = randomGrease(11);
    final int supportedGroupGrease = GreaseUtil.randomGrease();
    addSupportedGroupsExtension(clientExtensions, supportedGroupGrease, // X25519Kyber768Draft00,
        X25519MLKEM768, NamedGroup.x25519, NamedGroup.secp256r1, NamedGroup.secp384r1);
    addSignatureAlgorithmsExtension(clientExtensions,
        SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_secp256r1_sha256),
        SignatureAndHashAlgorithm.rsa_pss_rsae_sha256,
        SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha256),
        SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_secp384r1_sha384),
        SignatureAndHashAlgorithm.rsa_pss_rsae_sha384,
        SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha384),
        SignatureAndHashAlgorithm.rsa_pss_rsae_sha512,
        SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha512));
    TlsExtensionsUtils.addCompressCertificateExtension(clientExtensions,
        new int[] {CertificateCompressionAlgorithm.brotli});
    TlsExtensionsUtils.addPSKKeyExchangeModesExtension(clientExtensions, new short[] {PskKeyExchangeMode.psk_dhe_ke});
    addApplicationSettingsExtension(clientExtensions);
    // clientExtensions.put(ExtensionType.encrypted_client_hello, Hex.decodeStrict(
    // "000001000138002054b1fcc8868629a9ec88d5b183f9e26917229f69035b4ac94e833dd431bc4a5e00902f73c090762306de7f3fe1bd8d6ea5e4a577715d7385301e7340140f2970e5e58ad4c6584456035ec1f079afbbba4ad0e1292e3b7dfc3f9305a863e4b152c6880def239a16843469fbc2a46846b2a2007b6d97a4d5f897f5d6df2b33b31e3f306ac3f4fe5d229dfffe3dcf209c710430d8f4bb97b86be8ef1437425a3c693dfed5afa5c7ad0b84965060bd10d805cee0"));
    clientExtensions.put(ExtensionType.encrypted_client_hello, Hex.decodeStrict(
        "00000100019a0020e6a6a3ba4f85a0a65843cf7ea9f6d7dd5d35940922da0f107258e6c3ec585e5500904a2f77c19642f008b9ff0967f26c075af85b06c2bb56d03b9253c35cb853a919edb73433c2a1bd958fff963d4859df6b79b127be77d817f401f3d873ed6359e73e9f7bb243fb3df6832bb2dc7581e3f2c42e02b69edd93a79bb3b63cd7aaccb60c0ab77d2b80209bcc3b7789886ae40847723ee578af8390b39f8a4a8795dde9899adb793140dd57cc757d7d6bfd9c72"));
    randomExtension(clientExtensions, null, true);
    {

      Vector<PskIdentity> identities = new Vector<>();
      identities.add(new PskIdentity(new byte[113], 1));
      Vector<byte[]> binders = new Vector<>();
      binders.add(new byte[32]);
      TlsExtensionsUtils.addPreSharedKeyClientHello(clientExtensions, new OfferedPsks(identities, binders, 1));

      Vector<KeyShareEntry> keyShareEntries = TlsExtensionsUtils.getKeyShareClientHello(clientExtensions);
      if (keyShareEntries != null) {
        // final int X25519Kyber768Draft00 = 0x6399;
        // final int X25519MLKEM768 = 4588;
        // keyShareEntries.add(0, new KeyShareEntry(X25519Kyber768Draft00, new byte[1]));
        keyShareEntries.add(0, new KeyShareEntry(GreaseUtil.randomGrease(), new byte[1]));
        keyShareEntries.add(0, new KeyShareEntry(X25519MLKEM768, new byte[1216]));
        TlsExtensionsUtils.addKeyShareClientHello(clientExtensions, keyShareEntries);
      }

    }
  }
}
