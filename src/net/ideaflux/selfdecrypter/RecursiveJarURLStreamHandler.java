package net.ideaflux.selfdecrypter;

import java.io.IOException;
import java.net.JarURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;

public class RecursiveJarURLStreamHandler extends URLStreamHandler {
	protected URLConnection openConnection(URL u) throws IOException {
		return (JarURLConnection)u.openConnection();
	}
}
