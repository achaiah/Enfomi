package net.ideaflux.snippets;

/** 
 * Original Author: John Mitchell
 * Found at:		http://www.javaworld.com/javaworld/javatips/jw-javatip70.html
 */


public class JarClassLoader extends MultiClassLoader {
	private JarResources jarResources;

	public JarClassLoader(String jarName) {
		// Create the JarResource and suck in the jar file.
		jarResources = new JarResources(jarName);
	}

	protected byte[] loadClassBytes(String className) {
		// Support the MultiClassLoader's class name munging facility.
		className = formatClassName(className);
		// Attempt to get the class data from the JarResource.
		return (jarResources.getResource(className));
	}
}
