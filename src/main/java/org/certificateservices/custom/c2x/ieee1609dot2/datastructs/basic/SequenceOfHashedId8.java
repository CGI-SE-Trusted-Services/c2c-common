/************************************************************************
 *                                                                       *
 *  Certificate Service -  Car2Car Core                                  *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Affero General Public License   *
 *  License as published by the Free Software Foundation; either         *
 *  version 3   of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COERSequenceOf;

import java.util.List;


/**
 * Base type defining a sequence of HashedId8
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class SequenceOfHashedId8 extends COERSequenceOf {

	private static final long serialVersionUID = 1L;

	/**
	 * Constructor used when decoding
	 */
	public SequenceOfHashedId8(){
		super(new HashedId8());
	}

	/**
	 * Constructor used when encoding
	 */
	public SequenceOfHashedId8(HashedId8[] sequenceValues){
		super(sequenceValues);
	}

	/**
	 * Constructor used when encoding
	 */
	public SequenceOfHashedId8(List<HashedId8> sequenceValues){
		super((HashedId8[]) sequenceValues.toArray(new HashedId8[sequenceValues.size()]));
	}

	@Override
	public String toString() {
		String retval = "SequenceOfHashedId8 [";
		if(sequenceValues != null){
			for(int i=0; i< sequenceValues.length -1;i++){
				retval += new String(Hex.encode(((HashedId8) sequenceValues[i]).getHashedId())) + ",";
			}
			if(sequenceValues.length > 0){
				retval += new String(Hex.encode(((HashedId8) sequenceValues[sequenceValues.length-1]).getHashedId())) ;
			}
		}
		retval += "]";
		return retval;
	}
	
}
