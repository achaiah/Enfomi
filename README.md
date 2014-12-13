<h3>Overview</h3>
Enfomi was created because I have been dissatisfied with the offering of free encryption software out there. For a while, I have been using a PGP utility that also provided password-based encryption and created self-decrypting archives. I really liked the self-decrypting functionality but because it was Windows based I couldn't use it on any other platform. Probably the most mobile solution would have to be something that is written in Java. Unfortunately, none of the programs I have tried seemed to have the features I wanted (for the price I wanted). Long story short - here is my take on encryption. I am not claiming that it is bug free but I have tried to take all due care to ensure the security of encrypted data. Yes, I do eat my own dog food and have been using Enfomi for over 7 years.
<h3>Key Functionality</h3>
I believe Enfomi offers the most flexible solution available online.
<ol>
	<li>It provides up to 256-bit AES based encryption (for comparison, the current military standards require 128-bit encryption for top secret documents). It supports 28 different types of encryption (many 3DES, IDEA, AES variants)</li>
	<li>It can create self-decrypting archives, meaning that you do not need to carry the program with you, just the encrypted file. However, due to the overhead (about 1Mb) of stuff that needs to be stored with the self-decrypting version, you can also create stand-alone encrypted files.</li>
	<li>It allows you to select multiple files and folders to be encrypted into one file.</li>
	<li>All files are <span style="text-decoration: underline;">zipped</span> before being encrypted (thus making the archive a little more secure as well as saving space)</li>
	<li>Because Enfomi is written in Java, it should be able to run on any platform that has Java 1.7 or above.</li>
	<li>You should be able to run Enfomi (or a self-decrypting file created with Enfomi) simply by double-clicking on it.</li>
</ol>
<h3>Cost</h3>
Free!
<h3>License</h3>
<a title="Apache 2.0 license" href="http://www.apache.org/licenses/LICENSE-2.0.html" target="_blank">Apache v.2.0</a> (BouncyCastle encryption package is licensed under their own <a href="http://www.bouncycastle.org/licence.html" target="_blank">terms</a> - which are akin to a FreeBSD license)
<h3>Restrictions</h3>
<span style="color: #ff0000;">WARNING: This program contains strong encryption functionality (in excess of 128-bit). If you do not live in the United States of America, it may be a violation of your country's laws to download and use this program. It is your duty to review applicable laws and verify that you may indeed posess and utilize Enfomi. </span>

Please be aware that if you want to utilize encryption capabilities in excess of 128-bit then you will have to download and install Unlimited Strength Jurisdiction Policy Files. By default, Enfomi uses 128-bit AES encryption which, as pointed out above, is military grade and should be enough for any purpose. However, if you feel the need for stronger encryption, you can get the necessary policy files here:

<a title="Java 7 Policy Files" href="http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html" target="_blank">Java 7 Policy Files</a> -- <a title="Java 8 Policy Files" href="http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html" target="_blank">Java 8 Policy Files</a> (for all of these read the README in each respective download for installation instructions)
<h3>How to use</h3>
I hope that Enfomi is pretty easy and straight-forward to use. Depending on whether you are opening Enfomi application for the first time or a self-decrypting archive created with Enfomi, you may see two different screens.
<p style="text-align: center;">MAIN SCREEN</p>
<p style="text-align: center;"><a href="http://www.ideaflux.net/pictures/Enfomi/OSX/mainWindow.jpg" target="_blank"><img class="aligncenter" src="http://www.ideaflux.net/pictures/Enfomi/OSX/mainWindowThumb.jpg" alt="Main Screen" /></a> <a href="http://www.ideaflux.net/pictures/Enfomi/Win7/mainWindow.jpg" target="_blank"><img class="aligncenter" src="http://www.ideaflux.net/pictures/Enfomi/Win7/mainWindowThumb.jpg" alt="Windows 7" /></a></p>
<p style="text-align: left;">The main screen is shown above. By default it is pre-set to encrypt files and folders that you add to the list by either dragging and dropping them onto the main screen or by clicking the "+" button. To successfully encrypt something follow these steps:</p>

<ol>
	<li>Enter passphrase in the provided box</li>
	<li>Choose "encrypt" (default) as your desired option</li>
	<li>Add files and/or directories to the list by either dragging &amp; dropping them or clicking the "+" button</li>
	<li>Optionally, browse for a folder (directory) where you want to save your resulting encrypted file</li>
	<li>Review additional settings under the "Options" tab (described below)</li>
	<li>Click "Encrypt" and confirm (retype) your passphrase when prompted</li>
	<li>You'll see a window informing you that encryption is in progress. Depending on the size of your files and your computer this might take a bit of time. Please be patient. Enfomi will tell you when it's done.</li>
</ol>
<p style="text-align: center;">OPTIONS SCREEN</p>
<p style="text-align: center;"><a title="Options Screen" href="http://www.ideaflux.net/pictures/Enfomi/OSX/optionsWindow.jpg" target="_blank"><img class="aligncenter" src="http://www.ideaflux.net/pictures/Enfomi/OSX/optionsWindowThumb.jpg" alt="Options Window" /></a> <a href="http://www.ideaflux.net/pictures/Enfomi/Win7/optionsWindow.jpg" target="_blank"><img src="http://www.ideaflux.net/pictures/Enfomi/Win7/optionsWindowThumb.jpg" alt="Windows 7" /></a></p>
This screen should be self-explanatory, and has been preset with the most common desired settings. Here you can change/select two things.
<ol>
	<li>Whether you want a self-decrypting archive (this is recommended and means that the Enfomi program will be packaged as part of the encrypted file that is created)</li>
	<li>Your algorithm of choice (preset to a very secure selection but without bothering you to install additional cryptography policies - see "How to get" for an expanded explanation)</li>
</ol>
<p style="text-align: center;">DECRYPTION SCREEN</p>
<p style="text-align: center;"><a href="http://www.ideaflux.net/pictures/Enfomi/OSX/alreadyArchive.jpg" target="_blank"><img class="aligncenter" src="http://www.ideaflux.net/pictures/Enfomi/OSX/alreadyArchiveThumb.jpg" alt="Decryption screen" /></a> <a href="http://www.ideaflux.net/pictures/Enfomi/Win7/alreadyArchive.jpg" target="_blank"><img class="aligncenter" src="http://www.ideaflux.net/pictures/Enfomi/Win7/alreadyArchiveThumb.jpg" alt="Decryption screen" /></a></p>
This screen will be presented if the file you have double-clicked is a self-decrypting archive created with Enfomi. You have a couple of choices here:
<ol>
	<li>To decrypt the data contained in the encrypted file, type in your passphrase, select the directory to decrypt data to and hit "Decrypt"</li>
	<li>Because the self-decrypting archive contains the whole Enfomi program, you can use any self-decrypting file to encrypt more data (that will be stored in a separate file). If you hit the "Go to main screen" button you will see the familiar screens described above and will have the full flexibility to create further encrypted files.</li>
</ol>
<h3>New Features in Version 1.3.1</h3>
<ol>
	<li>Automatically prefill the "Encrypt To: / Decrypt To:" fields with the directory from which Enfomi was launched. That was high on my annoyance list as you always had to browse first to select your location.</li>
	<li>Added confirmation dialog during encryption if the resulting file already exists. No more accidental overwrites!</li>
	<li>Updated the list of available cyphers.</li>
	<li>Fixed a nasty nasty bug that caused nested folders to not always be archived correctly.</li>
	<li>Made Enfomi run exclusively on Java 7 and above. Yes, this is by design. Older versions of Java really did not provide the support I needed to make this tool execute properly</li>
	<li>Thanks to Java 7, moved all input/output streams to use the "try-with-resources" programming pattern. No more hang-ups on piped streams.</li>
	<li>Added countdown latches during encryption / decryption to make sure all threads finish their work.</li>
	<li>Transitioned to the Maven build process. This is a big deal. Now you go to build the code and magic happens!</li>
	<li>Moved code to an SVN repository. If you're looking for source code, look there. The CVS repository is now obsolete.</li>
</ol>
<h3>New Features in Version 1.2</h3>
<ol>
	<li>Drag and drop functionality now available. Whew... no more clicking that pesky '+' button and having to browse!</li>
	<li>The keyboard DELETE key will now remove any selected files from the list.</li>
	<li>A lot more (and friendlier!) error reporting (for those of you who like to delete files from the hard drive after adding them to the encryption list ... tsk tsk tsk)</li>
	<li>Files with the same name (but coming from different folders) will now be listed with a (1), (2), etc. after the name to show you that the names are the same.
Please keep in mind though that Enfomi does not store parent folder information while encrypting so it will preserve only the folder structure of the top-level folders that were added to the encryption list. This means that any files with the same name in the encryption list will be renamed by Enfomi to avoid conflicts during decryption.</li>
</ol>
<h3>FAQ</h3>
I will do my best to answer any questions below, left in the comments or otherwise. Here are the most common problems and answers.

<em>Enfomi claims that my password is incorrect during encryption/decryption even though I know I have provided the right password.</em>
You might see this error for a couple of reasons. One of the most typical ones is that you are trying to encrypt or decrypt a file that uses encryption in excess of 128-bit and you do not have the correct policy files installed. Please look above in the "How to get" section to learn about installation of correct policy files.

<em>Can I add more files to the already encrypted archive? </em>
No, sorry. At this point if you want to add more files you will have to decrypt your archive, add new files and re-encrypt with Enfomi (frankly I'd have to do this behind the scenes for you anyway).

<em>Will compressing my files before encryption save space? </em>
No it will not! If you look in the features list, Enfomi already performs zip compression on all files before encrypting them. You will not gain any benefit by compressing your files beforehand.

<em>My files over 1.4GB in size become unusable (Enfomi cannot decrypt them again).</em>
Update your version of Enfomi please. Since v1.3.1, Enfomi runs only on Java7 and later. This is a deliberate decision due to the shortcomings of Java 5 and 6.
<h3>Future Releases Roadmap</h3>
<ol>
	<li>Extract the BC jar to current dir if temp fails. If both fail then give up.</li>
	<li>Create a headless version.</li>
</ol>