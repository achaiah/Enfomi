package net.ideaflux.snippets;

import java.security.*;
import java.util.*;


/*
 * The code below will list all strings that can be used with a specific provider
 * Adapted from: http://forum.java.sun.com/thread.jspa?messageID=9412157
 */
public class ListProviderEncryptionStrings {
	public static void main(String[] args) throws Exception {
		Provider provider = new org.bouncycastle.jce.provider.BouncyCastleProvider();
		Security.addProvider(provider);
		
		Set<String> algs = new HashSet<String>();
		
		System.out.println("Provider : " + provider.getName());
		for (Enumeration en = provider.propertyNames(); en.hasMoreElements();) {
			String alg = (String) en.nextElement();
			if (alg.matches("(?i)cipher.*?pbe.*")) {
				alg = alg.replaceFirst("(?i).*?(?=pbe)", "");
				if (!algs.contains(alg)) {
					algs.add(alg);
					System.out.println(alg);
				}
			}
		}
	}
}
