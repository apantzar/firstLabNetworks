/*
	*      SDES Calculator SDESApplet Class
	*
	*      Change History:
	*
	*
	*			Simplified DES Calculator
	*			Copyright (C) 2003  Robert A. Beezer
	*
	*			This program is free software; you can redistribute it and/or
	*			modify it under the terms of the GNU General Public License
	*			as published by the Free Software Foundation; either version 2
	*			of the License, or (at your option) any later version.
	*
	*			This program is distributed in the hope that it will be useful,
	*			but WITHOUT ANY WARRANTY; without even the implied warranty of
	*			MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	*			GNU General Public License for more details.
	*
	*			You should have received a copy of the GNU General Public License
	*			along with this program; if not, write to the Free Software
	*			Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
	*
	 * Simplified DES simulator
	 *
	 *    Author: Robert Beezer <beezer@ups.edu>
	 *    Date:   May 9 - 19, 2003
	 *
	 *    Simplified DES (SDES) is a "toy" symmetric encryption algorithm created by Ed Schaefer.
	 *    It is meant for instructional purposes as a companion to Data Encryption Standard (DES).
	 *    The idea is to impart a feeling for the *real* DES without the large amount of computation
	 *    that is required of industrial-strength DES.
	 *    Still, computing SDES can be error-prone and tedious.  This calculator will do the 
	 *    necessary computations, while exposing each and every intermediate result on request.  
	 *    With this tool, a student can work out examples by hand (which is preferable in this case)
	 *    while checking the intermediate steps so that errors do not propogate.
	 *    
	 *    As such, the coding of the algorithm is nowhere near as efficient as it could be,
	 *    since each intermediate result must be captured.
	 *    
	 *    The interested user should consult one of the references below for a complete
	 *    treatment of SDES.  I've relied mostly on Stallings during development.
	 *
	 *
	 *  References: 
	 *    Stallings, William.  "Cryptography and Network Security", 2nd Edition
	 *    Barr, Invitation to Cryptology, 1st edition, Prentice Hall, 2002
	 *    Schaefer, E. "A Simplified Data Encryption Standard," Cryptologia, January 1996 
	 *   
	 *
	 *   File List:
	 *     SDES.java:             Driver file for standalone version.
	 *     SDESApplet.java:    Driver file for applet version.
	 *     SDESUI.java:					Panel with all user interface code, and broad outline of algorithm.
	 *     SDESBits.java:       Low-level operations for bit manipulation, based upon java.util.BitSet
	 *
	 *
	 *		Design decisions:
	 *		   1.  There are more data structures, and fewer method calls, than would be expected, 
	 *		        so as to make it easy to capture intermediate computations.  There's no real penalty
	 *		        in execution speed, just code length.
	 *
	 *      2.  If there was ever a screen capture done while the program was running, the information
	 *		        displayed would be consistent.  Thus some fields are made uneditable, until the Clear
	 *		        button is pressed.  Or when buttons are pressed (eg encrypt/decrypt) the fields are cleared.
	 *
	 *
	 */



import javax.swing.*;


public class SDESApplet extends JApplet {

	SDESUI aPanel;
	
  public SDESApplet( ){
  }
  
  public void init() {
  	setSize( SDESUI.BESTSIZE );
  	aPanel = new SDESUI( );
		getContentPane().add( aPanel );
    aPanel.setVisible( true );
  }

	public void start( ){
	}
 
} 