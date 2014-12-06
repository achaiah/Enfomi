/**
 * 
 */
package net.ideaflux.core;

import java.io.File;

/**
 * @author Ryan D. Brooks
 */
public final class Lib {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		System.out.println(new File(getJarPath(Lib.class)));
	}

	public static String getJarPath(Class base) {
		// the leading '/' tells getResource not to append the package name
		// (instead the leading / is just stripped off)
		String className = "/" + base.getName().replace('.', '/') + ".class";
		String path = base.getResource(className).getPath();

		int pos = path.lastIndexOf("!");
		if (pos == -1) { // class is not in a jar file
			return null;
		} else { // class is in a jar file
			String jarpath = path.substring("file:".length(), pos);
			return jarpath.replaceAll("%20", " ");
		}
	}
}
