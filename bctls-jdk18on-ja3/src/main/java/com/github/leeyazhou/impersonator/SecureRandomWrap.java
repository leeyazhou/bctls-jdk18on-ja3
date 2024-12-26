package com.github.leeyazhou.impersonator;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

import org.bouncycastle.tls.ClientHello;

public class SecureRandomWrap extends SecureRandom implements Impersonator {

	private static final long serialVersionUID = 1L;
	private final Impersonator impersonator;

	public SecureRandomWrap(Impersonator impersonator) {
		this.impersonator = impersonator;
	}

	@Override
	public byte[] generateSeed(int numBytes) {
		byte[] seed = new byte[numBytes];
		ThreadLocalRandom.current().nextBytes(seed);
		return seed;
	}

	@Override
	public void nextBytes(byte[] bytes) {
		ThreadLocalRandom.current().nextBytes(bytes);
	}

	@Override
	public int[] getCipherSuites() {
		return impersonator.getCipherSuites();
	}

	@Override
	public void onEstablishSession(Map<Integer, byte[]> clientExtensions) throws IOException {
		impersonator.onEstablishSession(clientExtensions);
	}

	@Override
	public void onSendClientHelloMessage(ClientHello clientHello, Map<Integer, byte[]> clientExtensions)
			throws IOException {
		impersonator.onSendClientHelloMessage(clientHello, clientExtensions);
	}

}
