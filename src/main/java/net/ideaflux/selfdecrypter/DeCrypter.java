/**
 * Copyright 2007-2014 Alexei Samoylov
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.ideaflux.selfdecrypter;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.PushbackInputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.concurrent.CountDownLatch;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarInputStream;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import javax.crypto.NoSuchPaddingException;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.SpringLayout;


// import com.simontuffs.onejar.JarClassLoader;

/**
 * @author Alexei Samoylov - achaiah@gmail.com
 *         Description of purpose: This class encrypts and decrypts data using various algorithms as provided by
 *         bouncycastle.org "BC" provider. A self-decrypting jar or simple data files may
 *         be created.
 */
public class DeCrypter implements ActionListener {

	public static String versionNumberToShow = "v1.3";

	// Create a file chooser
	protected final JFileChooser fc = new JFileChooser();

	protected boolean unzipComplete = false; // used for threading to indicate that a pipe can be closed without repercussions
	protected boolean noEntriesFound = false;
	protected boolean containsData = false; // indicates that this archive contains data and is hopefully is self-decrypting

	protected JScrollPane listScroller;
	protected JTextField resultingLocURL = new JTextField(pwd + File.separator + "encryptedFile.jar");
	protected ButtonGroup radioButtons = new ButtonGroup();
	protected JRadioButton encryptRadio = new JRadioButton("Encrypt");
	protected JRadioButton decryptRadio = new JRadioButton("Decrypt");
	protected JCheckBox checkBox = new JCheckBox();
	protected JTabbedPane tabbedPane;
	JPanel optionsPanel;
	
	// Set default encrypt/decrypt directory to PWD
	private static Path currentRelativePath = Paths.get("");
	public static String pwd = currentRelativePath.toAbsolutePath().toString();

	protected JButton locationBrowseButton;
	protected JButton addFileButton;
	protected JButton removeFileButton;
	protected JButton decryptButton;
	protected JButton okButton;
	protected JButton cancelButton;
	protected JButton yesButton;
	protected JButton somethingElseButton;
	protected JButton decryptResultButton;

	protected JTextArea hasArchive = new JTextArea("This file already contains an encrypted archive.  Type a password, select a directory and click 'Decrypt' " + "to decrypt it or click 'Go to main screen' for other options.");
	private JPasswordField passField;

	protected final JLabel decryptToLabel = new JLabel("Decrypt To: ");
	protected final JLabel encryptToLabel = new JLabel("Encrypt To: ");
	protected final JLabel fileLabel = new JLabel("File(s): ");
	protected final JLabel passLabel = new JLabel("Passphrase: ");
	protected final JLabel fileSizeLabel = new JLabel("Total size: 0K");

	protected CustomFileList selectedFiles = new CustomFileList(fileSizeLabel);

	protected File dir = new File(pwd + File.separator + "encryptedFile.jar");
	protected JPanel encryptPanel;
	protected JPanel fileListPanel; // contains list of files to be encrypted/decrypted
	protected SpringLayout layout = new SpringLayout();
	protected JFrame aframe;
//	protected PipedInputStream pis, dpis;
//	protected PipedOutputStream pos, dpos;
	protected String encryptionAlgoName = "PBEWITHSHA256AND256BITAES-CBC-BC";
	protected JDialog waitDialog = null; // a dialog that shows a waiting message while we encrypt/decrypt

	protected File bcTempFile = null;

	protected Class<?> BCProvider = null;

	protected final String dataFileName = "data";
	protected final String bcProvLibrary = "/lib/bcprov-ext-jdk15-146.jar";

	// -- options tab elements -- //
	protected ButtonGroup fileOutputOptions = new ButtonGroup();
	protected JRadioButton selfDecryptOption = new JRadioButton("Create Self-Decrypting Archive");
	protected JRadioButton singleFileOption = new JRadioButton("Create Encrypted File Only");
	protected JComboBox AlgoSelectBox;

	protected CountDownLatch latch;


	/**
	 * Create the GUI and show it. For thread safety,
	 * this method should be invoked from the
	 * event-dispatching thread.
	 */
	private void createAndShowGUI(JFrame frame) {

		aframe = frame;

		passField = new JPasswordField();
		passField.setEchoChar('*'); // sets blocking character

		// set the BC security provider before we begin
		addSecurityProviders();

		if (!determineIfSpecialUI()) {
			buildMainUI();
		}
		else dir = new File(pwd);
	}


	private void addSecurityProviders() {
		boolean tryHardCodedLocation = false; // indicates whether a bc.jar came packaged within a jar we are running

		/** Normally we would call the line below but the provider needs dynamic loading so we instead do a lot of dancing around **/
		// Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		// System.out.println("Trying to get input stream");
		InputStream bcIn = this.getClass().getClassLoader().getResourceAsStream("bc.jar");
		if (bcIn != null) {
			try {
				bcTempFile = File.createTempFile("bcp", ".jar");
				// System.out.println("Temp file location: " + bcTempFile.getAbsolutePath());
				if (bcTempFile.canWrite()) { // hopefully we can write to the temp location
					FileOutputStream bcOut = new FileOutputStream(bcTempFile);
					byte[] b = new byte[8]; // read from jar location and write to temp location
					int i = bcIn.read(b);
					while (i != -1) {
						bcOut.write(b, 0, i);
						i = bcIn.read(b);
					}

					// now do the class loader
					// System.out.println("loading provider from internal bc.jar");
					URL[] urlLocations = new URL[1];
					urlLocations[0] = bcTempFile.toURI().toURL();
					URLClassLoader classLoader = new URLClassLoader(urlLocations);
					// TODO load dynamically from jar
					// URL url = this.getClass().getClassLoader().getResource("bc.jar");
					// urlLocations[0] = url;
					// URLClassLoader classLoader = new URLClassLoader(urlLocations, ClassLoader.getSystemClassLoader(), new IdeafluxURLStreamHandlerFactory());
					BCProvider = classLoader.loadClass("org.bouncycastle.jce.provider.BouncyCastleProvider");
				}
			}
			catch (IOException e) {
				e.printStackTrace();
			}
			catch (ClassNotFoundException e) {
				e.printStackTrace();
			}
		}
		else tryHardCodedLocation = true; // else try loading from a relative hardcoded path

		// load the provider from a set location
		if (tryHardCodedLocation) {
			System.out.println("Loading provider from a hardcoded location...");
			ClassLoader classLoader = ClassLoader.getSystemClassLoader();
			try {
				// if this line causes an exception then your bcprov*.jar file is not in the classpath
				BCProvider = classLoader.loadClass("org.bouncycastle.jce.provider.BouncyCastleProvider");
			}
			catch (ClassNotFoundException e) {
				e.printStackTrace();
			}
		}

		// add bouncyCastle provider.
		try {
			Security.addProvider((Provider) BCProvider.newInstance());
		}
		catch (InstantiationException e) {
			System.out.println("Failed to instantiate class.");
			e.printStackTrace();
		}
		catch (IllegalAccessException e) {
			System.out.println("Illegal Access to Class");
			e.printStackTrace();
		}

		// the sun JCE provider (also may be installed by default) Use "SunJCE" as provider string.
		// Provider sunJce = new com.sun.crypto.provider.SunJCE();
		// Security.addProvider(sunJce);
	}


	private void cleanup() {
		// get rid of the temp file
		if (bcTempFile != null) bcTempFile.deleteOnExit();
		// close waitDialog if it is open
		if (waitDialog != null) {
			if (waitDialog.isVisible()) {
				waitDialog.setVisible(false);
				waitDialog.dispose();
				waitDialog = null;
			}
		}
	}


	private void buildMainUI() {
		tabbedPane = new JTabbedPane();

		optionsPanel = new JPanel();

		// add tabbed pane to the frame
		aframe.add(tabbedPane);

		encryptPanel = new JPanel();
		tabbedPane.addTab("Encrypt", null, encryptPanel, "Encrypt a File");
		tabbedPane.setMnemonicAt(0, KeyEvent.VK_1);

		tabbedPane.addTab("Options", null, optionsPanel, "Set encrypt-decrypt options");
		tabbedPane.setMnemonicAt(1, KeyEvent.VK_2);

		// select which tab shows up first
		tabbedPane.setSelectedIndex(0);

		encryptPanel.setLayout(layout); // add springLayout

		// create file list with '+' and '-' buttons
		fileListPanel = new JPanel(new BorderLayout());

		addFileButton = new JButton("+");
		removeFileButton = new JButton("-");

		addFileButton.addActionListener(this);
		removeFileButton.addActionListener(this);

		JPanel fileButtonPanel = new JPanel();
		fileButtonPanel.setLayout(new BoxLayout(fileButtonPanel, BoxLayout.X_AXIS)); // vertical layout
		fileButtonPanel.add(addFileButton);
		fileButtonPanel.add(Box.createRigidArea(new Dimension(10, 2)));
		fileButtonPanel.add(removeFileButton);
		fileButtonPanel.add(Box.createHorizontalGlue());

		// add listPanel to the scroller
		listScroller = new JScrollPane(selectedFiles);

		fileListPanel.add(listScroller, BorderLayout.CENTER);
		fileListPanel.add(fileButtonPanel, BorderLayout.SOUTH);
		fileListPanel.setBackground(Color.white);

		fileButtonPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
		listScroller.setAlignmentX(Component.LEFT_ALIGNMENT);

		// Create Buttons
		okButton = new JButton("Encrypt");
		cancelButton = new JButton("Exit");
		locationBrowseButton = new JButton("Browse");

		okButton.addActionListener(this);
		cancelButton.addActionListener(this);
		locationBrowseButton.addActionListener(this);

		// set up radio buttons
		radioButtons.add(encryptRadio);
		radioButtons.add(decryptRadio);

		encryptRadio.addActionListener(this);
		decryptRadio.addActionListener(this);

		encryptRadio.setSelected(true);

		selectedFiles.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		selectedFiles.setLayoutOrientation(JList.VERTICAL);

		resultingLocURL.setEditable(false);

		// Encryption Tab --- In SpringLayout ORDER MATTERS TREMENDOUSLY
		encryptPanel.add(passLabel);
		layout.putConstraint(SpringLayout.WEST, passLabel, 5, SpringLayout.WEST, encryptPanel);
		layout.putConstraint(SpringLayout.NORTH, passLabel, 10, SpringLayout.NORTH, encryptPanel);
		encryptPanel.add(passField);
		layout.putConstraint(SpringLayout.EAST, passField, -5, SpringLayout.EAST, encryptPanel); // specifying this anchor BEFORE the line right below makes all the difference
		layout.putConstraint(SpringLayout.WEST, passField, 5, SpringLayout.EAST, passLabel); // <-- this line MUST appear after the one above or the passField will act detached
		layout.putConstraint(SpringLayout.NORTH, passField, 0, SpringLayout.NORTH, passLabel);

		encryptPanel.add(encryptRadio);
		layout.putConstraint(SpringLayout.WEST, encryptRadio, 0, SpringLayout.WEST, passLabel);
		layout.putConstraint(SpringLayout.NORTH, encryptRadio, 10, SpringLayout.SOUTH, passField);
		encryptPanel.add(decryptRadio);
		layout.putConstraint(SpringLayout.WEST, decryptRadio, 15, SpringLayout.EAST, encryptRadio);
		layout.putConstraint(SpringLayout.NORTH, decryptRadio, 0, SpringLayout.NORTH, encryptRadio);

		encryptPanel.add(fileLabel);
		layout.putConstraint(SpringLayout.WEST, fileLabel, 0, SpringLayout.WEST, encryptRadio);
		layout.putConstraint(SpringLayout.NORTH, fileLabel, 10, SpringLayout.SOUTH, encryptRadio);

		encryptPanel.add(fileListPanel);
		layout.putConstraint(SpringLayout.EAST, fileListPanel, -7, SpringLayout.EAST, encryptPanel);
		layout.putConstraint(SpringLayout.WEST, fileListPanel, 2, SpringLayout.EAST, fileLabel);
		layout.putConstraint(SpringLayout.SOUTH, fileListPanel, -40, SpringLayout.NORTH, encryptToLabel);
		layout.putConstraint(SpringLayout.NORTH, fileListPanel, 80, SpringLayout.NORTH, encryptPanel);

		encryptPanel.add(decryptToLabel);
		layout.putConstraint(SpringLayout.WEST, decryptToLabel, 0, SpringLayout.WEST, fileLabel);
		layout.putConstraint(SpringLayout.SOUTH, decryptToLabel, -15, SpringLayout.NORTH, cancelButton);
		decryptToLabel.setVisible(false);

		encryptPanel.add(encryptToLabel);
		layout.putConstraint(SpringLayout.WEST, encryptToLabel, 0, SpringLayout.WEST, fileLabel);
		layout.putConstraint(SpringLayout.SOUTH, encryptToLabel, -15, SpringLayout.NORTH, cancelButton);

		encryptPanel.add(fileSizeLabel);
		layout.putConstraint(SpringLayout.NORTH, fileSizeLabel, 5, SpringLayout.SOUTH, fileListPanel);
		layout.putConstraint(SpringLayout.WEST, fileSizeLabel, 0, SpringLayout.WEST, fileListPanel);

		encryptPanel.add(resultingLocURL);
		layout.putConstraint(SpringLayout.EAST, resultingLocURL, -5, SpringLayout.WEST, locationBrowseButton); // <-- ORDER MATTERS
		layout.putConstraint(SpringLayout.WEST, resultingLocURL, 5, SpringLayout.EAST, encryptToLabel); // <-- this line would have quite different behavior if swapped with above
		layout.putConstraint(SpringLayout.SOUTH, resultingLocURL, -10, SpringLayout.NORTH, cancelButton);

		encryptPanel.add(locationBrowseButton);
		// layout.putConstraint(SpringLayout.WEST, resultButton, 5, SpringLayout.EAST, resultURL);
		layout.putConstraint(SpringLayout.EAST, locationBrowseButton, -3, SpringLayout.EAST, encryptPanel);
		layout.putConstraint(SpringLayout.SOUTH, locationBrowseButton, -10, SpringLayout.NORTH, cancelButton);

		encryptPanel.add(cancelButton);
		layout.putConstraint(SpringLayout.WEST, cancelButton, 10, SpringLayout.WEST, encryptPanel);
		layout.putConstraint(SpringLayout.SOUTH, cancelButton, -10, SpringLayout.SOUTH, encryptPanel);

		encryptPanel.add(okButton);
		layout.putConstraint(SpringLayout.WEST, okButton, 30, SpringLayout.EAST, cancelButton);
		layout.putConstraint(SpringLayout.SOUTH, okButton, 0, SpringLayout.SOUTH, cancelButton);

		buildOptionsUI(optionsPanel);

		// Display the window.
		aframe.pack();
		aframe.setPreferredSize(new Dimension(600, 500));
		aframe.setSize(new Dimension(420, 400));
		aframe.setMinimumSize(new Dimension(420, 400));
		aframe.setLocationRelativeTo(null); // center on screen
		aframe.setVisible(true);
	}


	private void buildOptionsUI(JPanel optionsPanel) {
		SpringLayout optionsLayout = new SpringLayout();

		JLabel selectHeader = new JLabel("Type of output:");
		JLabel selectAlgorithm = new JLabel("Encryption Algorithm:");

		fileOutputOptions.add(selfDecryptOption);
		fileOutputOptions.add(singleFileOption);

		selfDecryptOption.addActionListener(this);
		singleFileOption.addActionListener(this);

		selfDecryptOption.setSelected(true);

//		String[] AlgoNames = { "PBEWITHSHAANDIDEA-CBC", "PBEWITHSHAAND3-KEYTRIPLEDES-CBC", "PBEWITHSHAAND2-KEYTRIPLEDES-CBC", "PBEWITHMD5AND192BITAES-CBC-OPENSSL", "PBEWITHSHAAND128BITRC4", "PBEWITHSHAAND40BITRC4", "PBEWITHMD5AND128BITAES-CBC-OPENSSL", "PBEWITHMD5ANDDES", "PBEWITHSHAAND192BITAES-CBC-BC", "PBEWITHMD5AND256BITAES-CBC-OPENSSL", "PBEWITHSHA256AND128BITAES-CBC-BC", "PBEWITHSHA1ANDDES", "PBEWITHSHA256AND192BITAES-CBC-BC", "PBEWITHSHAAND128BITAES-CBC-BC", "PBEWITHSHAAND128BITRC2-CBC", "PBEWITHSHAAND40BITRC2-CBC", "PBEWITHSHAANDTWOFISH-CBC", "PBEWITHMD5ANDRC2", "PBEWITHSHAAND256BITAES-CBC-BC", "PBEWITHSHA256AND256BITAES-CBC-BC", "PBEWITHSHA1ANDRC2" };
		String[] AlgoNames = { 
		"PBEWITHMD5AND128BITAES-CBC-OPENSSL", 
		"PBEWITHMD5ANDRC2", 
		"PBEWITHSHAAND2-KEYTRIPLEDES-CBC", 
		"PBEWITHSHA1ANDDES", 
		"PBEWITHSHAAND3-KEYTRIPLEDES-CBC", 
		"PBEWITHMD5AND192BITAES-CBC-OPENSSL", 
		"PBEWITHSHAAND128BITRC2-CBC", 
		"PBEWITHSHAAND192BITAES-CBC-BC", 
		"PBEWITHMD2ANDDES", 
		"PBEWITHSHA256AND256BITAES-CBC-BC", 
		"PBEWITHSHAAND128BITAES-CBC-BC", 
		"PBEWITHSHAAND40BITRC2-CBC", 
		"PBEWITHSHAAND128BITRC4", 
		"PBEWITHMD5ANDDES", 
		"PBEWITHSHA256AND128BITAES-CBC-BC", 
		"PBEWITHSHAAND256BITAES-CBC-BC", 
		"PBEWITHSHAANDIDEA-CBC", 
		"PBEWITHSHA256AND192BITAES-CBC-BC", 
		"PBEWITHSHA1ANDRC2", 
		"PBEWITHMD5AND256BITAES-CBC-OPENSSL", 
		"PBEWITHSHAANDTWOFISH-CBC", 
		"PBEWITHSHAAND40BITRC4" };
		
		// Create the combo box, select item at index 13.
		AlgoSelectBox = new JComboBox(AlgoNames);
		AlgoSelectBox.setSelectedIndex(13); // Indices start at 0
		AlgoSelectBox.setSize(new Dimension(200, 50));

		optionsPanel.setLayout(optionsLayout); // add springLayout

		optionsPanel.add(selectHeader);
		optionsLayout.putConstraint(SpringLayout.WEST, selectHeader, 10, SpringLayout.WEST, optionsPanel);
		optionsLayout.putConstraint(SpringLayout.NORTH, selectHeader, 10, SpringLayout.NORTH, optionsPanel);

		optionsPanel.add(selfDecryptOption);
		optionsLayout.putConstraint(SpringLayout.WEST, selfDecryptOption, 5, SpringLayout.WEST, selectHeader);
		optionsLayout.putConstraint(SpringLayout.NORTH, selfDecryptOption, 10, SpringLayout.SOUTH, selectHeader);

		optionsPanel.add(singleFileOption);
		optionsLayout.putConstraint(SpringLayout.WEST, singleFileOption, 0, SpringLayout.WEST, selfDecryptOption);
		optionsLayout.putConstraint(SpringLayout.NORTH, singleFileOption, 0, SpringLayout.SOUTH, selfDecryptOption);

		optionsPanel.add(selectAlgorithm);
		optionsLayout.putConstraint(SpringLayout.WEST, selectAlgorithm, 0, SpringLayout.WEST, selectHeader);
		optionsLayout.putConstraint(SpringLayout.NORTH, selectAlgorithm, 20, SpringLayout.SOUTH, singleFileOption);

		optionsPanel.add(AlgoSelectBox);
		optionsLayout.putConstraint(SpringLayout.WEST, AlgoSelectBox, 5, SpringLayout.WEST, selectAlgorithm);
		optionsLayout.putConstraint(SpringLayout.NORTH, AlgoSelectBox, 10, SpringLayout.SOUTH, selectAlgorithm);
	}


	private boolean determineIfSpecialUI() {
		URL dataLocation = this.getClass().getClassLoader().getResource(dataFileName);
		// System.out.println("data found at : " + dataLocation);
		// if this is not null then this jar already contains encrypted data, so display a different UI
		if (dataLocation != null) {

			containsData = true; // yes, we do have data inside this jar

			hasArchive.setLineWrap(true);
			hasArchive.setWrapStyleWord(true);
			hasArchive.setEditable(false);
			// passfield is the same as in the main GUI

			encryptPanel = new JPanel();
			aframe.add(encryptPanel);

			encryptPanel.setLayout(layout); // add springLayout

			// Create Buttons
			yesButton = new JButton("Decrypt");
			somethingElseButton = new JButton("Go to main screen");
			decryptResultButton = new JButton("Browse");

			yesButton.addActionListener(this);
			somethingElseButton.addActionListener(this);
			decryptResultButton.addActionListener(this);

			resultingLocURL.setText(pwd);
			resultingLocURL.setEditable(false);

			// add elements to the panel
			encryptPanel.add(passLabel);
			layout.putConstraint(SpringLayout.WEST, passLabel, 5, SpringLayout.WEST, encryptPanel);
			layout.putConstraint(SpringLayout.NORTH, passLabel, 10, SpringLayout.NORTH, encryptPanel);

			encryptPanel.add(passField);
			layout.putConstraint(SpringLayout.EAST, passField, -5, SpringLayout.EAST, encryptPanel);
			layout.putConstraint(SpringLayout.WEST, passField, 5, SpringLayout.EAST, passLabel);
			layout.putConstraint(SpringLayout.NORTH, passField, -5, SpringLayout.NORTH, passLabel);

			encryptPanel.add(hasArchive);
			layout.putConstraint(SpringLayout.EAST, hasArchive, -7, SpringLayout.EAST, encryptPanel);
			layout.putConstraint(SpringLayout.WEST, hasArchive, 0, SpringLayout.WEST, passField);
			layout.putConstraint(SpringLayout.SOUTH, hasArchive, -15, SpringLayout.NORTH, decryptToLabel);
			layout.putConstraint(SpringLayout.NORTH, hasArchive, 15, SpringLayout.SOUTH, passField);

			encryptPanel.add(decryptToLabel);
			layout.putConstraint(SpringLayout.WEST, decryptToLabel, 0, SpringLayout.WEST, passLabel);
			layout.putConstraint(SpringLayout.SOUTH, decryptToLabel, -35, SpringLayout.NORTH, yesButton);

			encryptPanel.add(resultingLocURL);
			layout.putConstraint(SpringLayout.NORTH, resultingLocURL, -3, SpringLayout.NORTH, decryptToLabel);
			layout.putConstraint(SpringLayout.EAST, resultingLocURL, -5, SpringLayout.WEST, decryptResultButton);
			layout.putConstraint(SpringLayout.WEST, resultingLocURL, 5, SpringLayout.EAST, decryptToLabel);

			encryptPanel.add(decryptResultButton);
			layout.putConstraint(SpringLayout.EAST, decryptResultButton, -5, SpringLayout.EAST, encryptPanel);
			layout.putConstraint(SpringLayout.NORTH, decryptResultButton, 0, SpringLayout.NORTH, resultingLocURL);

			encryptPanel.add(somethingElseButton);
			layout.putConstraint(SpringLayout.WEST, somethingElseButton, 0, SpringLayout.WEST, hasArchive);
			layout.putConstraint(SpringLayout.SOUTH, somethingElseButton, -10, SpringLayout.SOUTH, encryptPanel);

			encryptPanel.add(yesButton);
			layout.putConstraint(SpringLayout.WEST, yesButton, 35, SpringLayout.EAST, somethingElseButton);
			layout.putConstraint(SpringLayout.NORTH, yesButton, 0, SpringLayout.NORTH, somethingElseButton);

			// Display the window.
			aframe.pack();
			aframe.setPreferredSize(new Dimension(600, 500));
			aframe.setMinimumSize(new Dimension(400, 250));
			aframe.setSize(new Dimension(400, 250));
			aframe.setLocationRelativeTo(null); // center on screen
			aframe.setVisible(true);

			return true;
		}
		return false;
	}


	public boolean doPasswordMatch() {
		boolean isMatching = false;
		JPasswordField reenterPassField = new JPasswordField(25); // 25 is the number of columns
		JLabel infoLabel = new JLabel("Please re-type your passphrase.");

		// array of objects to be displayed by the custom dialog
		Object[] array = { infoLabel, reenterPassField };

		CustomDialog passDialog = new CustomDialog(aframe, array);
		passDialog.pack();
		passDialog.setLocationRelativeTo(aframe);
		passDialog.setVisible(true);

		Object returnValue = passDialog.getJOptionPane().getValue();

		if (returnValue.equals(JOptionPane.CLOSED_OPTION) || returnValue.equals(JOptionPane.CANCEL_OPTION)) {
			System.out.println("User has closed the dialog or canceled out of it.");
			return false;
		}
		else if (returnValue.equals(JOptionPane.OK_OPTION)) {

			System.out.println("JOptionPane value: " + passDialog.getJOptionPane().getValue());
			isMatching = isPassphraseCorrect(passField.getPassword(), reenterPassField.getPassword());

			if (!isMatching) {
				JOptionPane.showMessageDialog(null, "Sorry your passphrases did not match.  Please try again.", "Mismatch", JOptionPane.ERROR_MESSAGE);
			}
		}

		// zero out the 2nd passfield
		reenterPassField.setText(null);
		return isMatching;
	}


	/**
	 * Returns true if passphrases match. Else returns false.
	 */
	public boolean isPassphraseCorrect(char[] origPass, char[] thisPass) {

		if (thisPass == null || origPass == null) return false;

		if (thisPass.length != origPass.length) return false; // make sure passphrases are equal length
		for (int i = 0; i < thisPass.length; i++) {
			if (thisPass[i] != origPass[i]) return false; // if a single char doesn't match, return false
		}
		return true;
	}


	public void actionPerformed(ActionEvent e) {
		// In response to a button click
		if (e.getSource() == addFileButton) {
			// adjust the selection window to allow multiple file selection for encryption or only one for decryption
			if (encryptRadio.isSelected()) {
				fc.setDialogTitle("Select files to encrypt");
				fc.setMultiSelectionEnabled(true);
				fc.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
			}
			else if (decryptRadio.isSelected()) {
				fc.setDialogTitle("Select files to decrypt");
				fc.setMultiSelectionEnabled(true);
				fc.setFileSelectionMode(JFileChooser.FILES_ONLY);
			}

			int returnVal = fc.showOpenDialog(tabbedPane);
			if (returnVal == JFileChooser.APPROVE_OPTION) {
				File[] files = new File[0];
				files = fc.getSelectedFiles(); // for multiple files (during encryption)
				if (files.length > 0) {
					selectedFiles.addFiles(files);
					if (encryptRadio.isSelected() && dir == null) {
						dir = new File(files[0].getParentFile().getAbsolutePath() + File.separator + "myEncryptedFile.jar"); // assign a default name to encrypt to
					}
					else if (decryptRadio.isSelected() && dir == null) dir = files[0].getParentFile();
					resultingLocURL.setText(dir.getAbsolutePath());
				}
			}
		}
		else if (e.getSource() == removeFileButton) { // remove any files that were selected from the list
			selectedFiles.removeCurrentlySelectedFiles();
		}
		else if (e.getSource() == locationBrowseButton) {
			fc.setDialogTitle("Where to Save Result?");
			int returnVal = -1;
			fc.setMultiSelectionEnabled(false);
			// show slightly different dialogs for decryption and encryption
			// recall that we encrypt to a single jar file, so show a "save" dialog box
			if (encryptRadio.isSelected()) {
				fc.setDialogTitle("Encrypt data to ..?");
				fc.setFileSelectionMode(JFileChooser.FILES_ONLY);
				returnVal = fc.showSaveDialog(tabbedPane);
			}
			// for decryption show an "open" dialog box where one can select a directory
			else if (decryptRadio.isSelected()) {
				fc.setDialogTitle("Decrypt data to ..?");
				fc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
				returnVal = fc.showOpenDialog(tabbedPane);
			}
			if (returnVal == JFileChooser.APPROVE_OPTION) {
				// again slightly different depending on encryption or decryption choice
				if (encryptRadio.isSelected()) {
					// append .jar to file name if user didn't add the extension
					if (!fc.getSelectedFile().getAbsolutePath().endsWith(".jar")) {
						dir = new File(fc.getSelectedFile().getAbsolutePath() + ".jar");
					}
					else dir = new File(fc.getSelectedFile().getAbsolutePath());
				}
				else if (decryptRadio.isSelected()) dir = fc.getSelectedFile();

				if (dir != null) resultingLocURL.setText(dir.getAbsolutePath());
			}
		}
		else if (e.getSource() == encryptRadio) {
			decryptToLabel.setVisible(false);
			encryptToLabel.setVisible(true);
			// any time we switch from one button to another, we reset our parameters
			resultingLocURL.setText(pwd + File.separator + "encryptedFile.jar");
			selectedFiles.clearList();
			dir = new File(pwd + File.separator + "encryptedFile.jar");
			// selectedFiles.setListData(instructions);
			okButton.setText("Encrypt");
			tabbedPane.setEnabledAt(tabbedPane.indexOfComponent(optionsPanel), true);
			tabbedPane.setTitleAt(tabbedPane.indexOfComponent(encryptPanel), "Encrypt");
		}
		else if (e.getSource() == decryptRadio) {
			encryptToLabel.setVisible(false);
			decryptToLabel.setVisible(true);
			// any time we switch from one button to another, we reset our parameters
			resultingLocURL.setText(pwd);
			selectedFiles.clearList();
			dir = new File(pwd);
			// selectedFiles.setListData(instructions);
			okButton.setText("Decrypt");
			tabbedPane.setEnabledAt(tabbedPane.indexOfComponent(optionsPanel), false);
			tabbedPane.setTitleAt(tabbedPane.indexOfComponent(encryptPanel), "Decrypt");
		}
		else if (e.getSource() == okButton) {
			if (selectedFiles.getFiles().size() == 0)
				JOptionPane.showMessageDialog(aframe, "Please select at least one file to be encrypted.");
			else if (passField.getPassword().length == 0)
				JOptionPane.showMessageDialog(aframe, "Please type in a passphrase.");
			else if (dir == null)
				JOptionPane.showMessageDialog(aframe, "Please select a directory for the encrypted file.");
			else doCryptography();
		}
		else if (e.getSource() == decryptResultButton) { // happens when an encrypted data archive is already present
			int returnVal = -1;
			fc.setMultiSelectionEnabled(false);
			fc.setDialogTitle("Decrypt data to ..?");
			fc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
			System.out.println("before showing dialog");
			returnVal = fc.showOpenDialog(encryptPanel);
			if (returnVal == JFileChooser.APPROVE_OPTION) {
				dir = fc.getSelectedFile();
				if (dir != null) resultingLocURL.setText(dir.getAbsolutePath());
			}
		}
		else if (e.getSource() == somethingElseButton) {
			aframe.remove(encryptPanel);
			buildMainUI();
		}
		else if (e.getSource() == yesButton) {
			if (passField.getPassword().length == 0)
				JOptionPane.showMessageDialog(aframe, "Please type in a passphrase.");
			else if (dir == null)
				JOptionPane.showMessageDialog(aframe, "Please select decryption location.");
			else {
				showProgressDialog(false);
				// we do encryption in its own thread, otherwise it really hogs
				// the main event handling thread of which actionPerformed() is part
				// Note: this method is called from within the actionPerformed() method
				Runnable runB = new Runnable() {

					public void run() {
						decrypt("", true); // in this case the fileLocation string inside decrypt() is not used
					}
				};
				Thread threadB = new Thread(runB, "threadB");
				threadB.start();
			}
		}
		else if (e.getSource() == cancelButton) {
			aframe.dispose();
		}

		// from options tab
		else if (e.getSource() == selfDecryptOption) {
		}
		else if (e.getSource() == singleFileOption) {
		}
	}


	/** calculate size of file in KB or recurse on directories */
	public static double getFileSize(File file) {
		double fileSize = 0.0;
		if (file.exists()) { // if file or directory exists
			if (file.isDirectory()) { // if this is a directory
				for (File f : file.listFiles()) { // for every file in the directory
					fileSize = fileSize + getFileSize(f); // get the size recursively
				}
			}
			else fileSize = file.length() / 1024.0; // otherwise just get the length of this file
		}
		return fileSize;
	}


	private void showProgressDialog(boolean encrypting) {

		String title = "Encrypting...";
		String message = "  Please wait while we encrypt your data...";

		if (!encrypting) {
			title = "Decrypting...";
			message = "  Please wait while we decrypt your data...";
		}

		waitDialog = new JDialog(aframe, title, false);
		// display a small window to let the users know that decrypting is in progress
		JLabel waitLabel = new JLabel(message);
		waitDialog.add(waitLabel, BorderLayout.CENTER);
		waitDialog.setLocationRelativeTo(aframe);
		waitDialog.setPreferredSize(new Dimension(300, 100));
		waitDialog.pack();
		waitDialog.setVisible(true);
	}


	private void doCryptography() {

		if (encryptRadio.isSelected()) {
			if (dir != null) {
				if (doPasswordMatch()) {
					showProgressDialog(true);

					// we do encryption in its own thread, otherwise it really hogs
					// the main event handling thread of which actionPerformed() is part
					// Note: this method is called from within the actionPerformed() method
					Runnable runB = new Runnable() {

						public void run() {
							// encrypt
							encrypt(dir);
						}
					};
					Thread threadB = new Thread(runB, "threadB");
					threadB.start();
				}
			}
			else System.err.println("dir was null");
		}
		else if (decryptRadio.isSelected()) {
			if (selectedFiles.getFiles().size() > 0) {
				showProgressDialog(false);
				// we do decryption in its own thread, otherwise it really hogs
				// the main event handling thread of which actionPerformed() is part
				// Note: this method is called from within the actionPerformed() method
				Runnable runB = new Runnable() {

					public void run() {
						// encrypt
						for (File file : selectedFiles.getFiles().values()) {
							decrypt(file.getAbsolutePath(), false); // we decrypt only one jar file at a time, false=external jar
						}
					}
				};
				Thread threadB = new Thread(runB, "threadB");
				threadB.start();
			}
			else System.err.println("File is either null or more than one was selected");
		}
		else System.err.println("No such option");

	}


	/**
	 * The method that performs encryption on one file at a time
	 * 
	 * @param enFile
	 */
	private void encrypt(File enFile) {
		String fileName = enFile.getAbsolutePath();
		javax.crypto.spec.PBEKeySpec pbeKeySpec;
		javax.crypto.spec.PBEParameterSpec PBEps;
		char[] passString;
		SecureRandom secureRandom;
		boolean isEncrSuccessful = true;

		encryptionAlgoName = (String) AlgoSelectBox.getSelectedItem();

		// TODO: based on the algorithm name, set the size of salt

		// Salt - used so that an attacker cannot use pre-made dictionaries of hashes to guess the password.
		// Instead, the attacker must compute each hash for every dictionary word once the salt is known.
		// Computing hashes is a mathematically intensive process.
		// It is especially useful if the salt is randomly generated every time. That way one message may
		// suffer but the rest of the messages are safe.
		// Salt can be transmitted in the clear along with the count.
		// Salt should be the same length as the digest (hash) algorithm that is used for encryption.
		// Standard digests -> MD5 = 128bits, SHA-1 = 160bits.
		byte[] salt = new byte[getSaltSize()];
		System.out.println("encrypting with salt length: " + salt.length);
		System.out.println("Encryption type: " + encryptionAlgoName);
		secureRandom = new SecureRandom();
		// this will fill out the salt with random bytes from the object
		secureRandom.nextBytes(salt);

		// Iteration count - makes it more difficult for the attacker to crack passwords (more time consuming)
		// Should be 1000 for weakest encryption
		int count = 10000;

		// Create the parameterSpec using salt and count
		PBEps = new javax.crypto.spec.PBEParameterSpec(salt, count);

		// get the password from the password field
		passString = passField.getPassword();
		
		// the password that is read should never be contained in a string since strings are immutable
		// and thus can linger around system memory. Instead use char[] and zero out the char[] after use
		// inside pbeKeySpec and anywhere else the password is stored.
		pbeKeySpec = new javax.crypto.spec.PBEKeySpec(passString); // this has another constructor with (passwd,salt,count,strength)

		// For DES, DES-EDE, and Blowfish read description below
		// somewhere in here I need to use a SecureRandom object which will create a new IV (init vector)
		// for further security
		// cipher.init(...) produces a random IV. This IV needs to be gotten using IVParameterSpec ivPS = new IVParameterSpec(ciper.getIV())
		// and passed along to the decrypting side
		// on the decrypting side: create an IvParameterSpec and pass it to the cipher.init(Cipher.DECRYPT_MODE, key, ivSpec)

		javax.crypto.Cipher c = null;
        try {
        	javax.crypto.SecretKey key = javax.crypto.SecretKeyFactory.getInstance(encryptionAlgoName, "BC").generateSecret(pbeKeySpec);
        	// System.out.println(asHex(key.getEncoded()));
    		// get instance of cipher using the specified provider
    		c = javax.crypto.Cipher.getInstance(encryptionAlgoName, "BC");
    		c.init(javax.crypto.Cipher.ENCRYPT_MODE, key, PBEps); // Initializes this cipher with a key and a set of algorithm parameters.
    		// System.out.println("initialized cipher");
        }
        catch (InvalidKeySpecException e1) {
	        e1.printStackTrace();
        }
        catch (NoSuchAlgorithmException e1) {
	        e1.printStackTrace();
        }
        catch (NoSuchProviderException e1) {
	        e1.printStackTrace();
        }
        catch (NoSuchPaddingException e) {
	        e.printStackTrace();
        }
        catch (InvalidKeyException e) {
	        e.printStackTrace();
        }
        catch (InvalidAlgorithmParameterException e) {
	        e.printStackTrace();
        }

		try (	// First open the file we will write to
				FileOutputStream fos = new FileOutputStream(fileName);
				// bind file output to a jar output
				JarOutputStream jos = new JarOutputStream(fos);
				
				// A PipedInputStream is created and connected to a PipedOutputStream that is feeding us the zipped data
				// in this case we interpose a cipher into a PipedInputStream to encode the data as we write it.
				PipedInputStream pis = new PipedInputStream();
				PipedOutputStream pos = new PipedOutputStream(pis);
				
				// commence reading from pis and writing to jos
				javax.crypto.CipherOutputStream cos = new javax.crypto.CipherOutputStream(jos, c);
				)
		
			{
			// Now we need to zip the data into a single file and encrypt it.
			// For security purposes we encrypt the data as we get the zipped OutputStream using PipedOutputStream
			JarEntry entry = null;

			// Make Manifest - first initiate the main attributes
			Manifest manifest = new Manifest();
			Attributes att = manifest.getMainAttributes();
			att.putValue("Main-Class", this.getClass().getName());
			/*
			 * Omigott ... apparently "Manifest-Version" MUST BE PRESENT before
			 * writing the manifest or the jar is created with a blank manifest. Note that NO Exceptions are thrown
			 * to let the coder know that this needs to be done. The manifest is just quietly replaced with a blank file.
			 * JavaDoc SUCKS!
			 * This issue is only documented in ONE place: http://java.sun.com/javase/6/docs/api/java/util/jar/Manifest.html#write(java.io.OutputStream)
			 */
			att.putValue("Manifest-Version", "1.0");
			att.putValue("Name", "net.ideaflux.decrypter");
			att.putValue("Self-Name", enFile.getName());
			// Sealing means that all classes defined in that package must be found in the same JAR file.
			// it provides a security measure to detect code tampering
			att.putValue("Sealed", "true");
			att.putValue("EncryptionAlgoName", encryptionAlgoName);
			att.putValue("count", Integer.toString(count));
			att.put(new Attributes.Name("saltLength"), Integer.toString(salt.length));

			// save salt as individual string values for the entire array
			for (int saltCount = 0; saltCount < salt.length; saltCount++) {
				att.put(new Attributes.Name(Integer.toString(saltCount)), Byte.toString(salt[saltCount]));
			}

			if (selfDecryptOption.isSelected()) { // then we create a jar with bc.jar, licenses and classFiles included

				// find all entries inside the jar
				JarFile myJarFile = getThisJarFile();
				Enumeration<JarEntry> oldEntries = myJarFile.entries();
				while (oldEntries.hasMoreElements()) {
					JarEntry je = (JarEntry) oldEntries.nextElement();
					String entryName = je.getName();
					// if it's neither manifest nor data itself
					if ((!entryName.contains(dataFileName)) && (!entryName.contains("MANIFEST"))) {
						
						try (InputStream entryInStream = myJarFile.getInputStream(je);) {
							jos.putNextEntry(je);

							System.out.println("Copying entry: " + entryName);
							byte[] b = new byte[8];
							int i = entryInStream.read(b);
							while (i != -1) {
								jos.write(b, 0, i);
								i = entryInStream.read(b);
							}
							jos.closeEntry();
						}
					}
				}
			}

			// write the entire manifest out to the jar
			jos.putNextEntry(new JarEntry("META-INF/MANIFEST.MF"));
			manifest.write(jos);
			jos.closeEntry();

			// finally write zipped and encrypted data
			entry = new JarEntry(dataFileName);
			jos.putNextEntry(entry);

			// We run the zip operation in a separate thread from the encryption operation
			Runnable runA = new Runnable() {

				public void run() {
					boolean success = false;
					try {
						success = zipFiles(pos, selectedFiles.getFiles());
					}
					catch (IOException e) {
						e.printStackTrace();
					}
					if (!success) {
						if (waitDialog != null) waitDialog.setVisible(false);
						return;
					}
				}
			};

			Thread threadA = new Thread(runA, "threadA");
			threadA.start();

			byte[] b = new byte[8];
			int i = pis.read(b);
			while (i != -1) {
				cos.write(b, 0, i);
				i = pis.read(b);
			}
			// flush all output streams TODO: may not be necessary after the try-with-resources change
			cos.flush();
			jos.flush();
			fos.flush();

			// close the last (data) Jar Entry
			jos.closeEntry();
		}
        catch (IOException e) {
	        // TODO Auto-generated catch block
	        e.printStackTrace();
        }

		// passField.getPassword() returns a char[] which needs to be zeroed out at the end
		for (int i = 0; i < passString.length; i++) {
			passString[i] = 'a';
		}

		// TODO: Jar should also be signed to prevent code replacement inside the jar

		if (isEncrSuccessful)
			JOptionPane.showMessageDialog(aframe, "Encryption successful");
		else JOptionPane.showMessageDialog(aframe, "Ooops we encountered an encryption error.  Please try again.");

		// reset variables
		isEncrSuccessful = true;

		// clean up
		cleanup();
	}


	private int getSaltSize() {
		if (encryptionAlgoName.contains("SHA256"))
			return 256;
		else if (encryptionAlgoName.contains("MD5"))
			return 128;
		else if (encryptionAlgoName.contains("SHA")) return 160;
		return 256; // by default
	}


	private void decrypt(String fileLocation, boolean internalLoc) {
		javax.crypto.Cipher cNew;
		javax.crypto.spec.PBEKeySpec pbeKeySpec;
		javax.crypto.spec.PBEParameterSpec PBEps;
		char[] passString;
		byte[] salt;
		int count;
		javax.crypto.CipherOutputStream dcos;

		boolean isDecrSuccessful = true;

		// get the password from the password field
		passString = passField.getPassword();
		pbeKeySpec = new javax.crypto.spec.PBEKeySpec(passString); // this has another constructor with (passwd,salt,count,strength)

		latch = new CountDownLatch(1);

		try (	PipedInputStream dpis = new PipedInputStream();
				PipedOutputStream dpos = new PipedOutputStream(dpis);
				)
		{
			// Now decrypt the same file (reverse the process)
			InputStream fis = null;
			JarInputStream jis = null;

			Manifest manifest = null;

			// commence reading from pis
			if (internalLoc) { // if this archive contains an encrypted file already, read it
				fis = this.getClass().getClassLoader().getResourceAsStream(dataFileName);
				// find the manifest internally
				// manifest = new Manifest(this.getClass().getClassLoader().getResourceAsStream("META-INF/MANIFEST.MF"));
				JarFile myJar = getThisJarFile();
				manifest = myJar.getManifest();
			}
			else { // else fileLocation points to the external file to decrypt
				   // System.out.println("Loading manifest from external jar: "+fileLocation);
				fis = new FileInputStream(fileLocation);
				jis = new JarInputStream(fis);

				// read manifest from jar
				JarFile jf = new JarFile(new File(fileLocation));
				manifest = jf.getManifest();

				// why the ... does the line below not work?!?
				// manifest = jis.getManifest();
			}

			Attributes att = manifest.getMainAttributes();

			// get salt + count from manifest and process
			int saltLength = Integer.parseInt(att.getValue("saltLength"));
			count = Integer.parseInt(att.getValue("count"));
			// System.out.println("Salt length read as: " + saltLength + "    count = " + count);
			salt = new byte[saltLength];
			// System.out.println("Filling Salt...");
			// restore salt values individually from string
			for (int saltCount = 0; saltCount < salt.length; saltCount++) {
				salt[saltCount] = Byte.parseByte(att.getValue(Integer.toString(saltCount)));
			}

			encryptionAlgoName = att.getValue("EncryptionAlgoName");

			// Create the parameterSpec using salt and count
			PBEps = new javax.crypto.spec.PBEParameterSpec(salt, count);
			javax.crypto.SecretKey key = javax.crypto.SecretKeyFactory.getInstance(encryptionAlgoName, "BC").generateSecret(pbeKeySpec);

			// Set the Ciper to decryption mode
			cNew = javax.crypto.Cipher.getInstance(encryptionAlgoName, "BC");
			cNew.init(javax.crypto.Cipher.DECRYPT_MODE, key, PBEps);

			dcos = new javax.crypto.CipherOutputStream(dpos, cNew);

			final ZipInputStream zin = new ZipInputStream(dpis);

			if (internalLoc) {
				// We run the unzip operation in a separate thread from the encryption operation
				// and pass in the dpis which will receive unencrypted data from the pipedOutputStream
				Runnable runB = new Runnable() {

					public void run() {
						try {
							unzipFiles(zin, dir);
						}
						catch (IOException e) {
							e.printStackTrace();
						}
					}
				};
				Thread threadB = new Thread(runB, "threadB");
				threadB.start();

				byte[] d = new byte[8];
				int i = fis.read(d);
				while (i != -1) {
					if (noEntriesFound) {
						JOptionPane.showMessageDialog(aframe, "Sorry, the data is invalid.  Did you type in the right passphrase?" + '\n' + "Try entering it again.");
						isDecrSuccessful = false;
						break;
					}
					// TODO: Race condition here, the 'if' above fails but before the rest of the 'else' below executes
					// the pipe becomes closed.
					else dcos.write(d, 0, i);
					i = fis.read(d);
				}
			}
			else {
				// position the stream at the beginning of a jar entry
				JarEntry inJarEntry = jis.getNextJarEntry();
				// System.out.println("EntryName: " + inJarEntry.getName());

				// skip for now every entry until you get to data entry
				while (!inJarEntry.getName().equalsIgnoreCase(dataFileName)) {
					inJarEntry = jis.getNextJarEntry();
					// System.out.println("Next EntryName: " + inJarEntry.getName());
				}

				// We run the unzip operation in a separate thread from the encryption operation
				// and pass in the dpis which will receive unencrypted data from the pipedOutputStream
				// Open the ZIP file
				Runnable runB = new Runnable() {

					public void run() {
						try {
							unzipFiles(zin, dir);
						}
						catch (IOException e) {
							e.printStackTrace();
						}
					}
				};
				Thread threadB = new Thread(runB, "threadB");
				threadB.start();

				byte[] d = new byte[8];
				int i = jis.read(d);
				while (i != -1) {
					if (noEntriesFound) {
						JOptionPane.showMessageDialog(aframe, "Sorry, the data is invalid.  Did you type in the right passphrase?" + '\n' + "Try entering it again.");
						isDecrSuccessful = false;
						break;
					}
					// TODO: Race condition here, the 'if' above fails but before the rest of the 'else' below executes
					// the pipe becomes closed.
					else dcos.write(d, 0, i);
					i = jis.read(d);
				}
			}

			dcos.flush();

			// doFinal() resets the cipher to its original state (but not necessary here, produces an error instead)

			latch.await(); // wait until zipped output stream finishes writing

			// while(!unzipComplete) { // wait for the unzipping thread to complete its operation
			// try { // otherwise this (main) thread quits and breaks the pipedOutputStream connection
			// Thread.sleep(500); // which results in an exception being thrown
			// } catch (InterruptedException e) {
			// System.out.println("decrypt thread interrupted");
			// e.printStackTrace();
			// }
			// }

			// TODO: closing this stream here will throw an exception upon decryption.
			// the error comes up when you first try to decrypt with the wrong passphrase and then with the correct one.
			// My guess is that it is because of the "final ZipInputStream zin" variable inside this method.
			// How do we fix this?
			// zin.close();
			if (jis != null) jis.close();
			if (fis != null) fis.close();

		}
		catch (java.security.NoSuchAlgorithmException nsae) {
			isDecrSuccessful = false;
			System.err.println(nsae.getMessage());
			JOptionPane.showMessageDialog(aframe, "Sorry, we couldn't find this encryption algorithm." + " Please notify the authors if this message is persistent.");
		}
		catch (java.security.InvalidKeyException ivke) {
			isDecrSuccessful = false;
			System.err.println(ivke.getMessage());
			JOptionPane.showMessageDialog(aframe, "Sorry you've typed in a wrong passphrase.  Please try again.");
		}
		catch (java.security.NoSuchProviderException nspe) {
			isDecrSuccessful = false;
			System.err.println(nspe.getMessage());
			JOptionPane.showMessageDialog(aframe, "Ooops, I've encountered a no such provider exception.  Bad bad computer!" + " Please tell the authors how you got here.");
		}
		catch (java.security.spec.InvalidKeySpecException ivkse) {
			isDecrSuccessful = false;
			System.err.println(ivkse.getMessage());
			JOptionPane.showMessageDialog(aframe, "Ooops, I've encountered an invalid key spec exception.  Bad bad computer!" + " Please tell the authors how you got here.");
		}
		catch (javax.crypto.NoSuchPaddingException nspe) {
			isDecrSuccessful = false;
			JOptionPane.showMessageDialog(aframe, "Ooops, I've encountered a padding exception.  Bad bad computer!" + " Please tell the authors how you got here.");
			System.err.println(nspe.getMessage());
		}
		catch (java.security.InvalidAlgorithmParameterException iape) {
			isDecrSuccessful = false;
			System.err.println(iape.getMessage());
			JOptionPane.showMessageDialog(aframe, "Ooops, I've encountered an invalid algo parameter exception.  Bad bad computer!" + " Please tell the authors how you got here.");
		}
		catch (IOException e) {
			System.err.println(e.getMessage());
			isDecrSuccessful = false;
			e.printStackTrace(System.out);
			JOptionPane.showMessageDialog(aframe, "Ooops, I've encountered an I/O exception.  Bad bad computer!" + " Please tell the authors how you got here.");
		}
		catch (InterruptedException e) {
			e.printStackTrace();
		}

		// passField.getPassword() returns a char[] which needs to be zeroed out at the end
		for (int i = 0; i < passString.length; i++) {
			passString[i] = 'a';
		}

		if (isDecrSuccessful) JOptionPane.showMessageDialog(aframe, "Sucess!  Decryption completed.");

		// reset variables for the next try
		isDecrSuccessful = true;
		noEntriesFound = false;

		// clean up after yourself at the end
		cleanup();
	}


	// Helper function to print out results as hex values
	public static String asHex(byte buf[]) {
		StringBuffer strbuf = new StringBuffer(buf.length * 2);
		int i;

		for (i = 0; i < buf.length; i++) {
			if (((int) buf[i] & 0xff) < 0x10) strbuf.append("0");

			strbuf.append(Long.toString((int) buf[i] & 0xff, 16));
		}

		return strbuf.toString();
	}


	/**
	 * @param args
	 */
	public static void main(String[] args) {

		// Map<String, String> sysMap = System.getenv();
		// for(Iterator<String> iter = sysMap.keySet().iterator(); iter.hasNext();) {
		// String key = iter.next();
		// System.out.println("Key: " + key + "    Value: " + sysMap.get(key));
		// }

		// Schedule a job for the event-dispatching thread:
		// creating and showing this application's GUI.
		javax.swing.SwingUtilities.invokeLater(new Runnable() {

			public void run() {
				// Create and set up the window.
				JFrame frame = new JFrame("Enfomi " + versionNumberToShow);
				frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
				DeCrypter decrypter = new DeCrypter();
				System.out.println("Current relative path is: " + DeCrypter.pwd);
				decrypter.createAndShowGUI(frame);
			}
		});
	}


	/**
	 * Zip files to an output stream
	 * Adapted from: http://www.exampledepot.com/egs/java.util.zip/CreateZip.html
	 * This should run in a separate thread
	 */
	private boolean zipFiles(PipedOutputStream pos, HashMap<String, File> files) throws IOException {
		/*
		 * from Java SE6.0 API
		 * A piped output stream can be connected to a piped input stream to create a communications pipe.
		 * The piped output stream is the sending end of the pipe. Typically, data is written to a PipedOutputStream
		 * object by one thread and data is read from the connected PipedInputStream by some other thread.
		 * Attempting to use both objects from a single thread is not recommended as it may deadlock the thread.
		 * The pipe is said to be broken if a thread that was reading data bytes from the connected piped
		 * input stream is no longer alive.
		 */
		boolean result = false;

		// Create a buffer for reading the files
		byte[] buf = new byte[4096];		// try to match it to a common block size

		try (ZipOutputStream out = new ZipOutputStream(pos);){
			// Compress the files
			for (String fileName : files.keySet()) {
				File file = files.get(fileName);
				if (!file.exists()) {
					JOptionPane.showMessageDialog(null, "Encryption Failed because file \n " + file.getAbsolutePath() + " was not found.", "File or Directory Not Found", JOptionPane.ERROR_MESSAGE);
					return false;
				}
				zipHelperRoutine(file, fileName, out, buf, "");
			}
			result = true;
		}
		catch (IOException e) {
			System.out.println("Zipping files failed inside zipFiles method");
			System.err.println(e.getMessage());
		}
		return result;
	}


	/**
	 * We pass in the fileName separately because there could be naming conflicts that must be resolved.
	 * For each file, if a naming conflict exists, the actual file name will have a '(#)' appended to it
	 * where the '#' is a sequential counter that helps uniquely to identify this file
	 * 
	 * @param file
	 * @param fileName
	 * @param zout
	 * @param buf
	 * @param relativePath
	 */
	private void zipHelperRoutine(File file, String fileName, ZipOutputStream zout, byte[] buf, String relativePath) {
			// if it's a file, just write to zout
			if (!file.isDirectory()) {
				try(FileInputStream in = new FileInputStream(file);) {
				// Add ZIP entry to output stream.
				zout.putNextEntry(new ZipEntry(relativePath + '/' + fileName));
				// System.out.println("Added zip entry: " + relativePath + '/' + file.getName());

				// Transfer bytes from the file to the ZIP file
				int len;
				while ((len = in.read(buf)) > 0) {
					zout.write(buf, 0, len);
				}

				// Complete the entry
				zout.closeEntry();
				}
				catch (FileNotFoundException e) {
					e.printStackTrace();
				}
				catch (IOException e) {
					e.printStackTrace();
				}
			}

			else { // recursively call ourselves on each 'file' inside this directory
				File[] files = file.listFiles();
				for (int i = 0; i < files.length; i++) {
					zipHelperRoutine(files[i], files[i].getName(), zout, buf, relativePath + '/' + fileName);
				}
			}
		
	}


	// helper method to find the location of this jar in the OS file system.
	private JarFile getThisJarFile() {
		try {
			File f = new File(getJarPath(this.getClass()));
			System.out.println("File = " + f.getAbsolutePath());

			return new JarFile(f);
		}
		catch (IOException e) {
			System.out.println("While returning from getJarFile");
			e.printStackTrace();
			return null;
		}

		// URL url = this.getClass().getClassLoader().getResource("bc.jar");
		// String st = url.toString();
		// JarURLConnection juc = (JarURLConnection)url.openConnection();
		// System.out.println("juc = " + juc.getEntryName());
		//
		// // can I also get a URL connection to the main file?
		//
		// URL modUrl = URI.create(st.substring(0, st.indexOf("!")+2)).toURL();
		// System.out.println("modUrl = " + modUrl.getFile());
		//
		// File newFile = new File(modUrl.getFile());
		// System.out.println("file = " + newFile.getAbsolutePath());
		//
		// JarURLConnection modJuc = (JarURLConnection)modUrl.openConnection();
		// System.out.println("modJuc = " + modJuc.getJarFile().getName());

		// JarInputStream jis = (JarInputStream)(.getContent());
		// System.out.println("getting this " + jis.getNextEntry().getName());
		// JarFile jf = new JarFile();
		// Enumeration en = jf.entries();
		// while (en.hasMoreElements()){
		// System.out.println("Entry name: " + ((Entry)en.nextElement()).getKey());
		// }
		// return jf;
	}


	public static String getJarPath(Class<?> base) {
		// the leading '/' tells getResource not to append the package name
		// (instead the leading / is just stripped off)
		String className = "/" + base.getName().replace('.', '/') + ".class";
		String path = base.getResource(className).getPath();

		int pos = path.lastIndexOf("!");
		if (pos == -1) { // class is not in a jar file
			return null;
		}
		else { // class is in a jar file
			String jarpath = path.substring("file:".length(), pos);
			return jarpath.replaceAll("%20", " ");
		}
	}


	private void jarHelperRoutine(File file, JarOutputStream jout, String relativePath, String excludeString) {
		if (file.getAbsolutePath().contains(excludeString)) return; // ignore all files that have an exclude string in their pathname
			// if it's a file, just write to zout
			if (!file.isDirectory()) {
				try(FileInputStream in = new FileInputStream(file);)
				{

					// Add JAR entry to output stream.
					jout.putNextEntry(new JarEntry(relativePath + '/' + file.getName()));
					System.out.println("Added jar entry: " + relativePath + '/' + file.getName());
	
					// Create a buffer for reading the files
					byte[] buf = new byte[1024];
	
					// Transfer bytes from the file to the JAR file
					int len;
					while ((len = in.read(buf)) > 0) {
						jout.write(buf, 0, len);
					}
	
					// Complete the entry
					jout.closeEntry();
				}
				catch (FileNotFoundException e) {
					e.printStackTrace();
				}
				catch (IOException e) {
					e.printStackTrace();
				}
			}

			else { // recursively call ourselves on each 'file' inside this directory
				File[] files = file.listFiles();
				for (int i = 0; i < files.length; i++) {
					jarHelperRoutine(files[i], jout, relativePath + '/' + file.getName(), excludeString);
				}
			}
	}


	// private void jarFiles(JarOutputStream jos) {
	//
	// JarEntry entry = new JarEntry(dataFileName);
	// //Write the entry to the output JAR
	// jos.putNextEntry(entry);
	// int read;
	// while ((read = jarIn.read(buf)) != -1) {
	// jarOut.write(buf, 0, read);
	// }
	// jarOut.closeEntry();
	// }

	/**
	 * Unzip files to an input stream
	 * Adapted from: http://www.exampledepot.com/egs/java.util.zip/GetZip.html
	 * This should run in a separate thread
	 * See description for inside zipFiles() on how to use PipedStreams
	 */
	private void unzipFiles(ZipInputStream zin, File dir) throws IOException {
		// Create a buffer for reading the files
		byte[] buf = new byte[1024];
		int countEntries = 0;

		try {
			// Get the first entry
			ZipEntry entry;
			entry = zin.getNextEntry();
			while (entry != null) {
				countEntries++;
				File saveMe = new File(dir.getAbsolutePath() + File.separator + entry.getName()); // get a file reference
				saveMe.getParentFile().mkdirs(); // make any necessary directories
				try(	// Open file for output
						FileOutputStream out = new FileOutputStream(saveMe);) {
					
					// Transfer bytes from the ZIP file to the output file
					int len;
					while ((len = zin.read(buf)) > 0) {
						out.write(buf, 0, len);
					}
				}
				entry = zin.getNextEntry();
			}
		}
		catch (IOException e) {
			System.err.println("Error inside unzipFiles " + e.getMessage());
			e.printStackTrace();
		}
		// if(!unzipComplete) unzipComplete=true;
		latch.countDown();
		if (countEntries == 0) noEntriesFound = true;
	}


	/**
	 * Reads user password from given input stream. Adapted from:
	 * http://java.sun.com/j2se/1.4.2/docs/guide/security/jce/JCERefGuide.html#PBEEx
	 */
	public static char[] readPasswd(InputStream in) throws IOException {
		char[] lineBuffer;
		char[] buf;

		buf = lineBuffer = new char[128];

		int room = buf.length;
		int offset = 0;
		int c;

		loop: while (true) {
			switch (c = in.read()) {
				case -1:
				case '\n':
					break loop;

				case '\r':
					int c2 = in.read();
					if ((c2 != '\n') && (c2 != -1)) {
						if (!(in instanceof PushbackInputStream)) {
							in = new PushbackInputStream(in);
						}
						((PushbackInputStream) in).unread(c2);
					}
					else break loop;

				default:
					if (--room < 0) {
						buf = new char[offset + 128];
						room = buf.length - offset - 1;
						System.arraycopy(lineBuffer, 0, buf, 0, offset);
						Arrays.fill(lineBuffer, ' ');
						lineBuffer = buf;
					}
					buf[offset++] = (char) c;
					break;
			}
		}

		if (offset == 0) {
			return null;
		}

		char[] ret = new char[offset];
		System.arraycopy(buf, 0, ret, 0, offset);
		Arrays.fill(buf, ' ');

		return ret;
	}
}

/*
 * The code below will list all strings that can be used with a specific provider
 * Found at: http://forum.java.sun.com/thread.jspa?messageID=9412157
 * import java.security.*;
 * import java.util.*;
 * public class Fred204
 * {
 * public static void main(String[] args) throws Exception
 * {
 * Provider provider = new org.bouncycastle.jce.provider.BouncyCastleProvider();
 * Security.addProvider(provider);
 * Set<String> algs = new HashSet<String>();
 * System.out.println("Provider : " + provider.getName());
 * for (Enumeration en = provider.propertyNames(); en.hasMoreElements();)
 * {
 * String alg = (String)en.nextElement();
 * if (alg.matches("(?i)cipher.*?pbe.*"))
 * {
 * alg = alg.replaceFirst("(?i).*?(?=pbe)", "");
 * if (!algs.contains(alg))
 * {
 * algs.add(alg);
 * System.out.println(alg);
 * }
 * }
 * }
 * }
 * }
 * Current strings for BC (v. 1.3.5)
 * Provider : BC
 * PBEWITHSHAANDIDEA-CBC
 * PBEWITHSHAAND3-KEYTRIPLEDES-CBC
 * PBEWITHSHAAND2-KEYTRIPLEDES-CBC
 * PBEWITHMD5AND192BITAES-CBC-OPENSSL
 * PBEWITHSHAAND128BITRC4
 * PBEWITHSHAAND40BITRC4
 * PBEWITHMD5AND128BITAES-CBC-OPENSSL
 * PBEWITHMD5ANDDES
 * PBEWITHSHAAND3-KEYTRIPLEDES-CBC
 * PBEWITHSHAAND192BITAES-CBC-BC
 * PBEWITHMD5AND256BITAES-CBC-OPENSSL
 * PBEWITHMD5ANDDES
 * PBEWITHSHA256AND128BITAES-CBC-BC
 * PBEWITHSHA1ANDDES
 * PBEWITHSHA256AND192BITAES-CBC-BC
 * PBEWITHSHAAND128BITAES-CBC-BC
 * PBEWITHSHA1ANDDES
 * PBEWITHSHAAND2-KEYTRIPLEDES-CBC
 * PBEWITHSHAAND128BITRC2-CBC
 * PBEWITHSHAAND40BITRC2-CBC
 * PBEWITHSHAANDTWOFISH-CBC
 * PBEWITHMD5ANDRC2
 * PBEWITHSHAANDTWOFISH-CBC
 * PBEWITHSHAAND256BITAES-CBC-BC
 * PBEWITHSHA256AND256BITAES-CBC-BC
 * PBEWITHSHA1ANDRC2
 */

// -- different ways of retrieving a manifest. Not all of them work -- //

// ClassLoader jarClassL = this.getClass().getClassLoader();
// Enumeration<URL> manifList = jarClassL.getResources("METADATAMANIFEST.MF");
//
// InputStream inFromJar=null;
//
// while(manifList.hasMoreElements()){
// String nextManif = manifList.nextElement().toString();
// System.out.println("Found manifest at: " + nextManif);
// inFromJar = this.getClass().getClassLoader().getResourceAsStream(nextManif);
// System.out.println("inFromJar = " + inFromJar);
// }

// System.out.println("Using getResource: " + jarClassL.getResource("META-INF/MANIFEST.MF").toString());
// System.out.println("Using getSystemResource: " + ClassLoader.getSystemResource("META-INF/MANIFEST.MF").toString());
// System.out.println("Using class.getResource: " + this.getClass().getResource("META-INF/MANIFEST.MF").toString());

// just a test with old stuff
// byte[] decryptedText = cNew.doFinal(cipherText);
// String tmp1 = new String(cipherText, "ASCII");
// String tmp2 = new String(decryptedText, "ASCII");
// String tmp = tmp1 + " = " + tmp2;
// System.out.println(tmp);
// PlainTextArea.setText(tmp);

// DEBUG :: list all attributes in the main attribute set
// att = manifest.getMainAttributes();
// Set<Entry<Object, Object>> entries = att.entrySet();
// for(java.util.Iterator iter = entries.iterator(); iter.hasNext();){
// System.out.println("Manifest attribute:>> "+iter.next().toString());
// }

// used earlier to read from command line input:
// Prompt user for encryption password.
// Collect user password as char array (using the "readPasswd" method from above), and convert
// it into a SecretKey object, using a PBE key factory.
// System.out.print("Enter encryption password:  ");
// System.out.flush();
// pbeKeySpec = new PBEKeySpec(readPasswd(System.in)); // TODO this has another constructor with (passwd,salt,count,strength)