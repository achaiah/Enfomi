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

// Adapted from: http://java.sun.com/docs/books/tutorial/uiswing/components/examples/CustomDialog.java

import java.awt.Frame;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;

import javax.swing.JDialog;
import javax.swing.JOptionPane;

class CustomDialog extends JDialog implements PropertyChangeListener {
	private static final long serialVersionUID = 1L;
    private JOptionPane optionPane;
    
    
    public JOptionPane getJOptionPane() {
    	return optionPane;
    }
    
    /** Creates the reusable dialog. */
    public CustomDialog(Frame aFrame, Object[] array) {
        super(aFrame, "Re-enter passphrase", true);
        
        //Create the JOptionPane.
        optionPane = new JOptionPane(array, JOptionPane.QUESTION_MESSAGE, JOptionPane.OK_CANCEL_OPTION);

        //Make this dialog display it.
        setContentPane(optionPane);
        
        //Register an event handler that reacts to option pane state changes.
        optionPane.addPropertyChangeListener(this);

        //Handle window closing correctly.
        setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);
        addWindowListener(new WindowAdapter() {
                public void windowClosing(WindowEvent we) {
                /*
                 * Instead of directly closing the window,
                 * we're going to change the JOptionPane's
                 * value property.
                 */
                    optionPane.setValue(new Integer(JOptionPane.CLOSED_OPTION));
            }
        });
    }
    
    /** This method reacts to state changes in the option pane. */
    public void propertyChange(PropertyChangeEvent e) {
        if (isVisible() && (e.getSource() == optionPane)) {
            setVisible(false);
        }
    }
}
