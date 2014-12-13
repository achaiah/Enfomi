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

import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.io.File;
import java.io.IOException;
import java.util.List;

import javax.swing.TransferHandler;

public class ListTransferHandler extends TransferHandler {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private CustomFileList list = null;
	
	
	/**
	 * Listens for drag and drop events and updates the list
	 * 
	 * @param list - the CustomFileList to update
	 */
	public ListTransferHandler(CustomFileList list) {
		super();
		this.list = list;
	}
	
	/**
	 * Only imports files and folders
	 */
	@Override
	public boolean canImport(TransferHandler.TransferSupport support) {
		if(!support.isDataFlavorSupported(DataFlavor.javaFileListFlavor)) return false;
		else return true;
	}
	
	/**
	 * Only imports files and folders.  Ignores duplicates.
	 */
	@Override
	public boolean importData(TransferSupport support) {
	    if (!canImport(support)) {
	        return false;
	    }

	    // Fetch the Transferable and its data
	    Transferable t = support.getTransferable();
	    List<File> fileList=null;
		try {
			fileList = (List<File>) t.getTransferData(DataFlavor.javaFileListFlavor);
		} catch (UnsupportedFlavorException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

	    // No need to fetch drop location, we will just insert files at the end

	    // Insert the new files
	    insertData(fileList);

	    return true;
	}
	
	/**
	 * Inserts the dropped files into the list
	 * @param files
	 */
	private void insertData(List<File> files) {
		list.addFiles((File[]) files.toArray());
	}
}
