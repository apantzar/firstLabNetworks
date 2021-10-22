/*
	*      SDES Calculator SDESBits Class
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


import java.util.BitSet;

class SDESBits extends BitSet {
	
	private int n;
	
	public SDESBits( int size ) {
		super( size );
		n = size;
	}
	
	public int getSize( ){
		return n;
	}
	
	public void swapHalves( ){
		if( ( n % 2) == 1 ){
			System.err.println( "SDESBits.swapHalves( ): Swapping halves on odd-length bit string" );
		}
		SDESBits temp = (SDESBits) clone( );
		for( int i = 0; i < n/2; i++ ){
			set( i, temp.get( i + n/2 ) );
			set( i + n/2, temp.get( i ) );
		}
	}

	public void leftShift( int start, int stop ){
	  boolean temp = get( start );
	  for( int i = start; i < stop; i++ ){
	  	set( i, get( i+1 ) );
	  }
	  set( stop, temp );
	 } 
	  

	public void permute( int[] aperm ){
		// aperm is the bottom row a 2xn representation 
		// of a permuation as an array of integer indices
		SDESBits temp = (SDESBits) clone( );
		for( int i = 0; i < n; i++ ){
			set( i, temp.get( aperm[i] ));
		}
	}
	  
	public void remove( int somebit ){
		// remove a bit, scoot others down one slot
		for(int i = somebit; i < (n-1); i++ ){
			set(i, get(i+1));
		}
		n--;
	}
	  
	public void expansion( ){
		if( n!= 4 ){
			System.err.println( "SDESBits.expansion( ): Operating on input with length unequal to 4" );
		}
		SDESBits temp = (SDESBits) clone( );
		n = 8;
		set( 0, temp.get(3) );
		set( 1, temp.get(0) );
		set( 2, temp.get(1) );
		set( 3, temp.get(2) );
		set( 4, temp.get(1) );
		set( 5, temp.get(2) );
		set( 6, temp.get(3) );
		set( 7, temp.get(0) );
	}
		
	
	public void leftHalf( ){
		if( n!= 8 ){
			System.err.println( "SDESBits.leftHalf( ): Operating on input with length unequal to 8" );
		}
		n = 4;
	}

	public void rightHalf( ){
		if( n!= 8 ){
			System.err.println( "SDESBits.rightHalf( ): Operating on input with length unequal to 8" );
		}
		n = 4;
		for( int i = 0; i < 4; i++ ){
			set(i, get(i+4) );
		}
	}

	public void sboxzero( ){
		if( n!= 4 ){
			System.err.println( "SDESBits.sboxzero( ): Operating on input with length unequal to 4" );
		}
		SDESBits temp = (SDESBits) clone( );
		n = 2;
		int[][] box = { {1,0,3,2}, {3,2,1,0}, {0,2,1,3}, {3,1,3,2} };
	  int row = 0;
	  if( temp.get(0) ){ row = row + 2; }
	  if( temp.get(3) ){ row = row + 1; }
	  int col = 0;
	  if( temp.get(1) ){ col = col + 2; }
	  if( temp.get(2) ){ col = col + 1; }
	  int result = box[row][col];
	  set( 0, (result / 2) == 1 );
	  set( 1, (result % 2) == 1 );
	 }

	public void sboxone( ){
		if( n!= 4 ){
			System.err.println( "SDESBits.sboxone( ): Operating on input with length unequal to 4" );
		}
		SDESBits temp = (SDESBits) clone( );
		n = 2;
		int[][] box = { {0,1,2,3}, {2,0,1,3}, {3,0,1,0}, {2,1,0,3} };
	  int row = 0;
	  if( temp.get(0) ){ row = row + 2; }
	  if( temp.get(3) ){ row = row + 1; }
	  int col = 0;
	  if( temp.get(1) ){ col = col + 2; }
	  if( temp.get(2) ){ col = col + 1; }
	  int result = box[row][col];
	  set( 0, (result / 2) == 1 );
	  set( 1, (result % 2) == 1 );
	 }

	public void xor( SDESBits bits ){
		if( this.n!= bits.getSize( ) ){
			System.err.println( "SDESBits.xor( ): XOR'ing inputs with unequal lengths" );
		}
		super.xor( bits );
	}

	public void append( SDESBits bits ){
		int m = bits.getSize( );
		for( int i = 0; i < m; i++ ){
			set( n+i, bits.get(i) );
		}
		n = n + m;
	}
	
	public Object clone( ){
		SDESBits acopy = (SDESBits) super.clone( );
		acopy.n = this.n;
		return acopy;
	}

	public String toString( ){
		StringBuffer outstring = new StringBuffer( );
		for( int i = 0; i < n; i++ ){
			if( get(i) ){
				outstring.append('1' );
			} else {
				outstring.append( '0' );
			}
		}
		return outstring.toString( );
	}

}
