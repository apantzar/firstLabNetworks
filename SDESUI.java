/*
	*      SDES Calculator SDESUI Class
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


import java.awt.*;
import java.awt.event.*;
import javax.swing.*;

class SDESUI extends JPanel implements ActionListener {

	// The intermediate steps are referenced by an enumerated type
	// For each step, there is a constant, and an SDES bit string
	// containing the result
	// MAX_OUT is the total number of steps here
	public static final int P10KEY         =  0;
	public static final int SHIFTKEY5      =  1;
	public static final int P8KEY1         =  2;
	public static final int SHIFTKEY2      =  3;
	public static final int P8KEY2         =  4;
	public static final int IPMESSAGE      =  5;
	public static final int RIGHTHALFR1    =  6;
	public static final int EXPANSIONR1    =  7;
	public static final int XORKR1         =  8;
	public static final int LEFTBOXR1      =  9;
	public static final int LEFTSBOX0R1    = 10;
	public static final int RIGHTBOXR1     = 11;
	public static final int RIGHTSBOX1R1   = 12;
	public static final int JOINNSBOXR1    = 13;
	public static final int P4R1           = 14;
	public static final int LEFTHALFR1     = 15;
	public static final int XORFR1         = 16;
	public static final int REPLACELEFTR1  = 17;
	public static final int SWAPHALVES     = 18;
	public static final int RIGHTHALFR2    = 19;
	public static final int EXPANSIONR2    = 20;
	public static final int XORKR2         = 21;
	public static final int LEFTBOXR2      = 22;
	public static final int LEFTSBOX0R2    = 23;
	public static final int RIGHTBOXR2     = 24;
	public static final int RIGHTSBOX1R2   = 25;
	public static final int JOINNSBOXR2    = 26;
	public static final int P4R2           = 27;
	public static final int LEFTHALFR2     = 28;
	public static final int XORFR2         = 29;
	public static final int REPLACELEFTR2  = 30;
	public static final int IPINV          = 31;
	public static final int MAX_OUT        = 32;
	
	// Each output gets a label, here they are
	// If we encrypt or decrypt, all is the same, except the
	// order in which subkeys are used, thus the two strings,
	// which we must interchange programmatically
	private static final String xork1string = "XOR with K1 (XOR)";
	private static final String xork2string = "XOR with K2 (XOR)";
	private static final String[] outputname = new String[ MAX_OUT ];
	static {
		outputname[ P10KEY ]          = "Key, Permute 10";
		outputname[ SHIFTKEY5 ]       = "Left Shift Key (on 5's)";
		outputname[ P8KEY1 ]          = "Key, Permute 8 (K1)";
		outputname[ SHIFTKEY2 ]       = "Key, Shift Left twice (on 5's)";
		outputname[ P8KEY2 ]          = "Key, Permute 8 (K2)";
		outputname[ IPMESSAGE ]       = "Initial Permutation (IP)";
		outputname[ RIGHTHALFR1 ]     = "Right Half of IP, Begin Round 1";
		outputname[ EXPANSIONR1 ]     = "Expansion Permutation";
		outputname[ XORKR1 ]          =  xork1string;
		outputname[ LEFTBOXR1 ]       = "Left Half of XOR";
		outputname[ LEFTSBOX0R1 ]     = "S-box Zero";
		outputname[ RIGHTBOXR1 ]      = "Right Half of XOR";
		outputname[ RIGHTSBOX1R1 ]    = "S-box One";
		outputname[ JOINNSBOXR1 ]     = "Join S-box Outputs";
		outputname[ P4R1 ]            = "Permute 4 (F)";
		outputname[ LEFTHALFR1 ]      = "Left Half of IP";
		outputname[ XORFR1 ]          = "XOR Left Half with F";
		outputname[ REPLACELEFTR1 ]   = "Replace Left Half of IP, End Round 1";
		outputname[ SWAPHALVES ]      = "Swap Halves (SW)";		
		outputname[ RIGHTHALFR2 ]     = "Right Half of SW, Begin Round 2";
		outputname[ EXPANSIONR2 ]     = "Expansion Permutation";
		outputname[ XORKR2 ]          =  xork2string;
		outputname[ LEFTBOXR2 ]       = "Left Half of XOR";
		outputname[ LEFTSBOX0R2 ]     = "S-box Zero";
		outputname[ RIGHTBOXR2 ]      = "Right Half of XOR";
		outputname[ RIGHTSBOX1R2 ]    = "S-box One";
		outputname[ JOINNSBOXR2 ]     = "Join S-box Outputs";
		outputname[ P4R2 ]            = "Permute 4 (F)";
		outputname[ LEFTHALFR2 ]      = "Left Half of SW";
		outputname[ XORFR2 ]          = "XOR Left Half with F";
		outputname[ REPLACELEFTR2 ]   = "Replace Left Half of SW, End Round 2";
		outputname[ IPINV ]           = "Inverse Initial Permutation, Result";
	}
	
	// Two text fields capture the main input
	public JTextField keytext;
	public JTextField messagetext;
	
	// The corresponding data for the main binary strings
	public SDESBits key;
	public SDESBits message;

	// A flag tracks if we have received input that is OK
	public boolean validinput;
	
	// When stepping through the computation, this integer tracks the progress
	public int step;
	
	// Two places give up dialogs with information, here's the necessary string
	public String docstring = 	"Simplified-DES Calculator, v1.0, May 2003\n"+
															"Copyright (C) 2003 Robert A. Beezer\n" +
															"<beezer@ups.edu>, http://buzzard.ups.edu\n" +
															"Licensed under GNU Public License (GPL)\n" +
															"and so comes with ABSOLUTELY NO WARRANTY.\n" +
															"This is free software, and you are welcome\n" +
													    "to redistribute it under certain conditions.\n" +
													    "See http://www.gnu.org/copyleft/gpl.html\n\n"+
													    "More documentation at http://buzzard.ups.edu/sdes/sdes.html";
	
	// Interface buttons
	public JRadioButton encryptbutton;
	public JRadioButton decryptbutton;
	public JButton stepbutton;
	public JButton allbutton;
	public JButton clearbutton;
	public JButton aboutbutton;
	
	// Principal data structures
	public SDESBits[] bits;				// The binary strings at each intermediate step
	public String[] textstring;		// String representations of results for eventual display
	public JLabel[] labels;				// Labels for fields next, need to reference two on-the-fly
	public JTextField[] text;   	// List of JTextFields for displaying strings above
	
	// Preferred sizing
	public static final Dimension BESTSIZE = 	new Dimension( 425, 800 );
	
	
	public SDESUI( ) {
	  //  Constructor with most of interface setup
		//  First, make space for two main input variables
		key = new SDESBits( 10 );
		message = new SDESBits( 8 );
		
		// Layout the labels and text fields for inputs
		JLabel keylabel = new JLabel("Key: ");
		keytext = new JTextField( 10 );
		keytext.setText( "Type 10 bits here" );
		keytext.setActionCommand( "Key bits" );
		keytext.addActionListener( this );
		
		JLabel messagelabel = new JLabel("Message: ");
		messagetext = new JTextField( 8 );
		messagetext.setText( "Type 8 bits here" );
		messagetext.setActionCommand( "Message bits" );
		messagetext.addActionListener( this );

		// Panels for labels and text fields
		JPanel labelPane = new JPanel();
		labelPane.setLayout(new GridLayout(0, 1));
		labelPane.add( keylabel );
		labelPane.add( messagelabel );

		JPanel fieldPane = new JPanel();
		fieldPane.setLayout(new GridLayout(0, 1));
		fieldPane.add( keytext );
		fieldPane.add( messagetext );

		// Allocate space for main data structures
		bits = new SDESBits[ MAX_OUT ];
		textstring = new String[ MAX_OUT ];
		labels = new JLabel[ MAX_OUT ];
		text = new JTextField[ MAX_OUT ];
		
		//  Allocate labels and fields
		for( int i = 0; i < MAX_OUT; i++ ){
			JLabel alabel = new JLabel( outputname[i] +  ": " );
			JTextField atextfield = new JTextField( 10 );
			atextfield.setEditable( false );
			labelPane.add( alabel );
			fieldPane.add( atextfield );
			labels[i] = alabel;
			text[i] = atextfield;
		}
		
		// Initialize everthing to prepare for new input
		clearFields( );

		//  Interface buttons along bottom of window
		JPanel buttonPane = new JPanel( );
		encryptbutton = new JRadioButton( "Encrypt" );
		encryptbutton.setSelected( true );  // Start-up behavior, consistent with lebels on "XOR key" outputs
		encryptbutton.setActionCommand( "encrypt" );
		encryptbutton.addActionListener( this );
		decryptbutton = new JRadioButton( "Decrypt" );
		decryptbutton.setActionCommand( "decrypt" );
		decryptbutton.addActionListener( this );
		ButtonGroup cryptgroup = new ButtonGroup( );
		cryptgroup.add( encryptbutton );
		cryptgroup.add( decryptbutton );		
		Box cryptbox = Box.createVerticalBox( );
		cryptbox.add( encryptbutton );
		cryptbox.add( decryptbutton );
		buttonPane.add( cryptbox );
		stepbutton = new JButton( "Step" );
		stepbutton.setActionCommand( "step" );
		stepbutton.addActionListener( this );
		buttonPane.add( stepbutton );
		allbutton = new JButton( "Compute" );
		allbutton.setActionCommand( "compute" );
		allbutton.addActionListener( this );
		buttonPane.add( allbutton );
		clearbutton = new JButton( "Clear" );
		clearbutton.setActionCommand( "clear" );
		clearbutton.addActionListener( this );
		buttonPane.add( clearbutton );
		aboutbutton = new JButton( "About" );
		aboutbutton.setActionCommand( "about" );
		aboutbutton.addActionListener( this );
		buttonPane.add( aboutbutton );
		
		// Put the panels in another panel, labels on left,
		// text fields on right, buttons on the bottom
		//The applet version looks better with a bit of space around the edge
		setBorder(BorderFactory.createEmptyBorder(5,20,5,20));
		setLayout(new BorderLayout());
		add( labelPane, BorderLayout.CENTER );
		add( fieldPane, BorderLayout.EAST );
		add( buttonPane, BorderLayout.SOUTH );
		//setSize( 900, 200 );

		JOptionPane.showMessageDialog(this, docstring, "Splash", JOptionPane.INFORMATION_MESSAGE);
		
	}

	
	public void actionPerformed( ActionEvent e ){
		//  Wire buttons to routines
		String command = e.getActionCommand( );
		
		if( command == "encrypt" ){
			// Changing these buttons invalidates display
			clearFields( );
			
			// Key 1 in Round 1, Key 2 in Round 2
			labels[ XORKR1 ].setText( xork1string );
			labels[ XORKR2 ].setText( xork2string );
		}
		
		if( command == "decrypt" ){
			// Changing these buttons invalidates display
			clearFields( );
			
			// Key 2 in Round 1, Key 1 in Round 2
			labels[ XORKR1 ].setText( xork2string );
			labels[ XORKR2 ].setText( xork1string );
		}
		
		if( command == "clear" ){
			clearFields( );
		}
		
		if( command == "compute" ){
			if( !validinput ){
				validinput = confirmInput( );
			}
			if( validinput ){
				step = MAX_OUT;
				display( step );
			}
		}
		
		if( command == "step" ){
			if( !validinput ){
				validinput = confirmInput( );
			}
			if( validinput ){
				if( step < MAX_OUT ){
					step = step + 1;
				}
				display( step );
			}
		}
	
		if( command == "about" ){
			JOptionPane.showMessageDialog(this, docstring, "About", JOptionPane.INFORMATION_MESSAGE);
		}

	}
	
	private void clearFields( ){
		// Open input fields, invalidate input, reset step, clear output fields
		keytext.setEditable( true );
		messagetext.setEditable( true );
		validinput = false;
		step = 0;
		for( int i = 0; i < MAX_OUT; i++ ){
			text[i].setText( "" );
		}
	}
	
	private boolean confirmInput( ){
		// Check 4 properties of input fields, return validity
		// If input is OK, we call for all the computations necessary
		// Lock up editability of text fields while here when input is OK
			boolean inputOK = true;	
			String messagestring = messagetext.getText( );
			String keystring = keytext.getText( );
			messagestring = messagestring.trim( );
			keystring = keystring.trim( );
			int messagevalue = -1;
			int keyvalue = -1;
			try{
				keyvalue = Integer.parseInt( keystring, 2 );
			} catch(Exception exc ){
				inputOK = false;
				JOptionPane.showMessageDialog(this, "Key must be a binary string", "Not Binary", JOptionPane.ERROR_MESSAGE);
			}
			if( inputOK ){			
				try{
					messagevalue = Integer.parseInt( messagestring, 2 );
				} catch(Exception exc ){
					inputOK = false;
					JOptionPane.showMessageDialog(this, "Message must be a binary string", "Not Binary", JOptionPane.ERROR_MESSAGE);
				}
			}
			if( inputOK ){
				inputOK = (keystring.length( ) == 10 ) && (keyvalue >= 0);
				if( !inputOK ){
					JOptionPane.showMessageDialog(this, "Key must be 10 bits long", "Wrong Length", JOptionPane.ERROR_MESSAGE);
				}
			}
			if( inputOK ){
				inputOK = (messagestring.length( ) == 8 ) && (messagevalue >= 0);
				if( !inputOK ){
					JOptionPane.showMessageDialog(this, "Message must be 8 bits long", "Wrong Length", JOptionPane.ERROR_MESSAGE);
				}
			}
			//  Now have determined if input is valid.  
			//  Do nothing with bad since we did dialogs above
			//  Run with good input, loading up bit strings, doing all computations
			
			if( inputOK ){
				for( int i = 0; i < 8; i++ ){
					char abit = messagestring.charAt( i );
					message.set( i, (abit == '1') );					
				}
				for( int i = 0; i < 10; i++ ){
					char abit = keystring.charAt( i );
					key.set( i, (abit == '1') );			
				}
				
				// Lock down any further fiddling on input filed
				messagetext.setEditable( false );
				keytext.setEditable( false );

				// We only get here once for valid input, so we can compute everything NOW
				compute( );
			}

		return inputOK;
	}
	
	
	private void display( int step ){
		for( int i = 0; i < step; i++ ){
			text[i].setText( textstring[i] );
		}
	}

	
	
	private void compute( ){
		// Convenience variable, runs through inter-mediate steps enumerated type
		int inter;
		
		// Various fixed permutations that are constant in the SDES algorithm
		final int[] ip    = {1,5,2,0,3,7,4,6};
		final int[] ipinv = {3,0,2,4,6,1,7,5};
	  final int[] p8    = {0,1,5,2,6,3,7,4,9,8};	
		final int[] p10   = {2,4,1,6,3,9,0,8,7,5};
		final int[] p4    = {1,3,2,0};

		// Determine immediately if we are encypting or decrypting
		// This  is only guaranteed to work right if 
		// (1) we select one of the encrypt/decrypt buttons at constructor time
		// (2) we keep the buttons in a logical ButtonGroup
		if( encryptbutton.isSelected( ) == decryptbutton.isSelected( ) ){
			System.err.println( "SDES.compute( ): Encrypt/Decrypt radio buttons out of synch" );
		}
		boolean encrypt = encryptbutton.isSelected( );

		// Begin key generation

		// Permute 10 bits of key by P10
		inter = P10KEY;
		bits[ inter ] = (SDESBits) key.clone( );
		bits[ inter ].permute( p10 );
		textstring[ inter ] = bits[ inter ].toString( );

		// Circular left shift, once, on each half
		inter = SHIFTKEY5;
		bits[ inter ] = (SDESBits) bits[ P10KEY ].clone( );
		bits[ inter ].leftShift( 0, 4 );
		bits[ inter ].leftShift( 5, 9 );
		textstring[ inter ] = bits[ inter ].toString( );
		
		// P8 permutation, drop leading two bits, result is K1
		inter = P8KEY1;
		bits[ inter ] = (SDESBits) bits[ SHIFTKEY5 ].clone( );
		bits[ inter ].permute( p8 );
		bits[ inter ].remove( 0 );
		bits[ inter ].remove( 0 );
		textstring[ inter ] = bits[ inter ].toString( );

		// Now two more circular shifts of full key
		inter = SHIFTKEY2;
		bits[ inter ] = (SDESBits) bits[ SHIFTKEY5 ].clone( );
		bits[ inter ].leftShift( 0, 4 );
		bits[ inter ].leftShift( 0, 4 );
		bits[ inter ].leftShift( 5, 9 );
		bits[ inter ].leftShift( 5, 9 );
		textstring[ inter ] = bits[ inter ].toString( );

		// P8 permutation, drop leading two bits, result is K2
		inter = P8KEY2;
		bits[ inter ] = (SDESBits) bits[ SHIFTKEY2 ].clone( );
		bits[ inter ].permute( p8 );
		bits[ inter ].remove( 0 );
		bits[ inter ].remove( 0 );
		textstring[ inter ] = bits[ inter ].toString( );

		// End key generation

		// Permute whole message with P10
		inter = IPMESSAGE;
		bits[ inter ] = (SDESBits) message.clone( );
		bits[ inter ].permute( ip );
		textstring[ inter ] = bits[ inter ].toString( );

		// Begin Round 1

		// Grab right half of permuted message text
		inter = RIGHTHALFR1;
		bits[ inter ] = (SDESBits) bits[ IPMESSAGE ].clone( );
		bits[ inter ].rightHalf( );
		textstring[ inter ] = bits[ inter ].toString( );

		// Expand right half to 8 bits
		inter = EXPANSIONR1;
		bits[ inter ] = (SDESBits) bits[ RIGHTHALFR1 ].clone( );
		bits[ inter ].expansion( );
		textstring[ inter ] = bits[ inter ].toString( );
		
		// XOR with key 1 or 2 (depending on function chosen)
		inter = XORKR1;
		bits[ inter ] = (SDESBits) bits[ EXPANSIONR1 ].clone( );
		if( encrypt ){
		  bits[ inter ].xor( bits[ P8KEY1 ] );
		} else {
			bits[ inter ].xor( bits[ P8KEY2 ] );
		}
		textstring[ inter ] = bits[ inter ].toString( );

		// Left half for S0
		inter = LEFTBOXR1;
		bits[ inter ] = (SDESBits) bits[ XORKR1 ].clone( );
		bits[ inter ].leftHalf( );
		textstring[ inter ] = bits[ inter ].toString( );
	
		// Left half thru S0
		inter = LEFTSBOX0R1;
		bits[ inter ] = (SDESBits) bits[ LEFTBOXR1 ].clone( );
		bits[ inter ].sboxzero( );
		textstring[ inter ] = bits[ inter ].toString( );
	
		// Right half for S1
		inter = RIGHTBOXR1;
		bits[ inter ] = (SDESBits) bits[ XORKR1 ].clone( );
		bits[ inter ].rightHalf( );
		textstring[ inter ] = bits[ inter ].toString( );
	
		// Right half thru S1
		inter = RIGHTSBOX1R1;
		bits[ inter ] = (SDESBits) bits[ RIGHTBOXR1 ].clone( );
		bits[ inter ].sboxone( );
		textstring[ inter ] = bits[ inter ].toString( );
	
		// Join halves from S-boxes
		inter = JOINNSBOXR1;
		bits[ inter ] = (SDESBits) bits[ LEFTSBOX0R1 ].clone( );
		bits[ inter ].append( bits[ RIGHTSBOX1R1 ] );
		textstring[ inter ] = bits[ inter ].toString( );

		// Permute 4-bit, creates big F
		inter = P4R1;
		bits[ inter ] = (SDESBits) bits[ JOINNSBOXR1 ].clone( );
		bits[ inter ].permute( p4 );
		textstring[ inter ] = bits[ inter ].toString( );
	
		// Grab left half of permuted message text
		inter = LEFTHALFR1;
		bits[ inter ] = (SDESBits) bits[ IPMESSAGE ].clone( );
		bits[ inter ].leftHalf( );
		textstring[ inter ] = bits[ inter ].toString( );

		// XOR left half of message with result of big F
		inter = XORFR1;
		bits[ inter ] = (SDESBits) bits[ LEFTHALFR1 ].clone( );
		bits[ inter ].xor( bits[ P4R1 ] );
		textstring[ inter ] = bits[ inter ].toString( );

		// Keep left half as is, restore righthalf
		inter = REPLACELEFTR1;
		bits[ inter ] = (SDESBits) bits[ XORFR1 ].clone( );
		bits[ inter ].append( bits[ RIGHTHALFR1 ] );
		textstring[ inter ] = bits[ inter ].toString( );
		
		// End Round 1
		
		// Swap halves , acts as  IPMESSAGE  in round 2 code recycle
		inter = SWAPHALVES;
		bits[ inter ] = (SDESBits) bits[ REPLACELEFTR1 ].clone( );
		bits[ inter ].swapHalves( );
		textstring[ inter ] = bits[ inter ].toString( );
	
	
		// Begin Round 2

		// Grab right half of permuted message text
		inter = RIGHTHALFR2;
		bits[ inter ] = (SDESBits) bits[ SWAPHALVES ].clone( );
		bits[ inter ].rightHalf( );
		textstring[ inter ] = bits[ inter ].toString( );

		// Expand right half to 8 bits
		inter = EXPANSIONR2;
		bits[ inter ] = (SDESBits) bits[ RIGHTHALFR2 ].clone( );
		bits[ inter ].expansion( );
		textstring[ inter ] = bits[ inter ].toString( );
		
		// XOR with key 2 or 1 (depending on function chosen)
		inter = XORKR2;
		bits[ inter ] = (SDESBits) bits[ EXPANSIONR2 ].clone( );
		if( encrypt ){
		  bits[ inter ].xor( bits[ P8KEY2 ] );
		} else {
			bits[ inter ].xor( bits[ P8KEY1 ] );
		}
		textstring[ inter ] = bits[ inter ].toString( );

		// Left half for S0
		inter = LEFTBOXR2;
		bits[ inter ] = (SDESBits) bits[ XORKR2 ].clone( );
		bits[ inter ].leftHalf( );
		textstring[ inter ] = bits[ inter ].toString( );
	
		// Left half thru S0
		inter = LEFTSBOX0R2;
		bits[ inter ] = (SDESBits) bits[ LEFTBOXR2 ].clone( );
		bits[ inter ].sboxzero( );
		textstring[ inter ] = bits[ inter ].toString( );
	
		// Right half for S1
		inter = RIGHTBOXR2;
		bits[ inter ] = (SDESBits) bits[ XORKR2 ].clone( );
		bits[ inter ].rightHalf( );
		textstring[ inter ] = bits[ inter ].toString( );
	
		// Right half thru S1
		inter = RIGHTSBOX1R2;
		bits[ inter ] = (SDESBits) bits[ RIGHTBOXR2 ].clone( );
		bits[ inter ].sboxone( );
		textstring[ inter ] = bits[ inter ].toString( );
	
		// Join halves from S-boxes
		inter = JOINNSBOXR2;
		bits[ inter ] = (SDESBits) bits[ LEFTSBOX0R2 ].clone( );
		bits[ inter ].append( bits[ RIGHTSBOX1R2 ] );
		textstring[ inter ] = bits[ inter ].toString( );

		// Permute 4-bit, creates big F
		inter = P4R2;
		bits[ inter ] = (SDESBits) bits[ JOINNSBOXR2 ].clone( );
		bits[ inter ].permute( p4 );
		textstring[ inter ] = bits[ inter ].toString( );
	
		// Grab left half of permuted message text
		inter = LEFTHALFR2;
		bits[ inter ] = (SDESBits) bits[ SWAPHALVES ].clone( );
		bits[ inter ].leftHalf( );
		textstring[ inter ] = bits[ inter ].toString( );

		// XOR left half of message with result of big F
		inter = XORFR2;
		bits[ inter ] = (SDESBits) bits[ LEFTHALFR2 ].clone( );
		bits[ inter ].xor( bits[ P4R2 ] );
		textstring[ inter ] = bits[ inter ].toString( );

		// Keep left half as is, restore righthalf
		inter = REPLACELEFTR2;
		bits[ inter ] = (SDESBits) bits[ XORFR2 ].clone( );
		bits[ inter ].append( bits[ RIGHTHALFR2 ] );
		textstring[ inter ] = bits[ inter ].toString( );
		
		// End Round 2	

		// Apply the inverse of P10 to finish
		inter = IPINV;
		bits[ inter ] = (SDESBits) bits[ REPLACELEFTR2 ].clone( );
		bits[ inter ].permute( ipinv );
		textstring[ inter ] = bits[ inter ].toString( );	
	}

}
