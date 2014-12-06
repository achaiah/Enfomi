package net.ideaflux.selfdecrypter;

import java.net.URLStreamHandler;
import java.net.URLStreamHandlerFactory;

public class IdeafluxURLStreamHandlerFactory implements URLStreamHandlerFactory {
	private static final RecursiveJarURLStreamHandler recursiveJarFactory = new RecursiveJarURLStreamHandler();
	public URLStreamHandler createURLStreamHandler(String protocol) {
		return recursiveJarFactory;
	}
}
