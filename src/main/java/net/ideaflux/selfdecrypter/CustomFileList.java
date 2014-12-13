/**
 * Copyright 2007-2011 Alexei Samoylov
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * 		http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.ideaflux.selfdecrypter;

import java.awt.event.ActionEvent;
import java.io.File;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map.Entry;
import java.util.Vector;

import javax.swing.AbstractAction;
import javax.swing.Action;
import javax.swing.DropMode;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;

public class CustomFileList extends JList {
	private static final long serialVersionUID = 1L;
	
	protected static String[] instructions = {"Click \"+\" button to add files or folders","or simply drag and drop into this space"};
	protected JLabel fileSizeLabel=null;
	
	private HashMap<String, File> nameToFileMap = new HashMap<String, File>();
	private HashMap<String, Double> nameToSize = new HashMap<String, Double>();
	
    /**
     * Constructor that takes as an argument a label to be updated with total file size
     */
    public CustomFileList(JLabel fileSizeLabel) {
		super(instructions);
		this.fileSizeLabel = fileSizeLabel;
		setDropMode(DropMode.ON_OR_INSERT);	// we want to be able to drop anywhere in the list
        setTransferHandler(new ListTransferHandler(this));
        
        // React to "DEL" and "BACKSPACE" key commands
        Action deleteAction = new AbstractAction() {
			private static final long serialVersionUID = 1L;

			public void actionPerformed(ActionEvent arg0) {
				removeCurrentlySelectedFiles();
			}
		};
        
        getInputMap().put(KeyStroke.getKeyStroke("DELETE"), "removeListFiles");
        getInputMap().put(KeyStroke.getKeyStroke("Backspace"), "removeListFiles");
        getActionMap().put("removeListFiles", deleteAction);
	}

	/** Updates the JList of file names with short names of the files (without listing the absolute path) */
    private void updateListData() {
    	double fileSize=0;
    	String sizeString = "Total size: 0K";
    	final Vector<String> names = new Vector<String>();
    	for(Entry<String, File> entry : nameToFileMap.entrySet()) {
    		names.add(entry.getKey());
    		
    		if(nameToSize.containsKey(entry.getKey())) {
    			fileSize = fileSize + nameToSize.get(entry.getKey());
    		}
    		else { // calculate file size and store it
    			double newSize = DeCrypter.getFileSize(entry.getValue());
    			nameToSize.put(entry.getKey(), newSize);
    			fileSize = fileSize + newSize;
    		}
    	}
    	if(names.size() > 0) {
    		if(fileSize/1024 > 10) {
    			if(fileSize/1048576 > 10) sizeString = "Total size: " + Math.round(fileSize/1048576) + "G";
    			else sizeString = "Total size: " + Math.round(fileSize/1024.0) + "M";
    		}
    		else sizeString = "Total size: " + Math.round(fileSize) + "K";
    	}
    	
    	// run on event dispatch thread
    	final String updateString = sizeString;
    	SwingUtilities.invokeLater(new Runnable() {
			public void run() {
				fileSizeLabel.setText(updateString);
				if(names.size() <= 0) {
		    		setListData(instructions);
		    	}
				else setListData(names);
			}
		});
    }
    
    
    /**
     * Attempts to add new files to the list.  Ignores if the same file has already been added once.
     * @param files - files to add
     */
    public void addFiles(File[] files) {
    	for(File file : files) {
    		if(!nameToFileMap.values().contains(file)) {	// first make sure that we're not trying to add the same file twice
	    		if(!nameToFileMap.containsKey(file.getName())) {
	    			nameToFileMap.put(file.getName(), file);
	    		}
	    		else {			// find a different name for this file using a counter
	//    			System.out.println("CustomFileList:: filename " + file.getName() + "  already exists!!");
	    			int counter=1;
	    	    	boolean nameFound=false;
	    	    	String newName = file.getName();
	    			while(!nameFound) {		// do file name conflict resolution until appropirate name has been found
	    				newName = file.getName() + " ("+counter+")";
	//	    				System.out.println("CustomFileList:: generated name is: " + newName);
	    				if(!nameToFileMap.containsKey(newName)) {
	    	    			nameToFileMap.put(newName, file);
	    	    			nameFound = true;
	    	    		}
	    				else counter++;
	    			}
				}
    		}
    	}
    	updateListData();
    }
    
    
    /**
     * Removes currently selected files from the file list
     */
    public void removeCurrentlySelectedFiles() {
    	removeFiles(getSelectedValues());
    }
    
    
    /**
     * Removes files based on a String name match with underlying file paths.
     * @param fileNames
     */
    public void removeFiles(Object[] fileNames) {
    	Object[] objectNames = fileNames;
		for(Object fileName : objectNames) {
//			System.out.println("Removing File: " + nameToFileMap.remove(fileName.toString()).getAbsolutePath());
			nameToFileMap.remove(fileName.toString());	// remove the entry from hashmap
			nameToSize.remove(fileName.toString());
		}
		updateListData();
    }
    
    
    /**
     * Removes all file entries and sets text in the list to default description
     */
    public void clearList() {
    	nameToFileMap.clear();		// clear our the list if switched to encryption
    	nameToSize.clear();
		updateListData();
    }
    
    
    /**
     * Returns a vector of files currently maintained by this list
     * @return
     */
    public HashMap<String, File> getFiles() {
    	return nameToFileMap;
    }
}
