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
package org.certificateservices.custom.c2x.asn1.coer;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * The encoding of a sequence-of value shall consist of a quantity field followed by the encodings of the occurrences of the component (of the same type and constraints). 
 * <p>
 * For more information see ISO/IEC 8825-7:2015 Section 17
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class COERSequenceOf implements COEREncodable {


	private static final long serialVersionUID = 1L;

	protected COEREncodable[] sequenceValues;
	protected COEREncodable emptyValue;
	protected byte[] emptyValueEncoded;

	/**
	 * Constructor used for decoding COER Sequence Of Values
	 * @param emptyValue a template COEREncodable (containing constraints) that is cloned for each decoded COER encodable object.
	 */
	public COERSequenceOf(COEREncodable emptyValue) {
		this.emptyValue = emptyValue;
		try {
			emptyValueEncoded = COEREncodeHelper.serialize(emptyValue);
		}catch (IOException e){
			throw new RuntimeException("Error creating object: " + e.getMessage(),e);
		}
		sequenceValues = null;
	}

	/**
	 * Constructor for encoding an array of COEREncodabe values (must be of the same type, with same constraints, otherwise use a sequence).
	 */
	public COERSequenceOf(COEREncodable[] sequenceValues){
		this.sequenceValues = sequenceValues;
	}

	/**
	 * Constructor for encoding an list of COEREncodabe values (must be of the same type, with same constraints, otherwise use a sequence).
	 */
	public COERSequenceOf(List<COEREncodable> sequenceValues){
		this.sequenceValues = sequenceValues.toArray(new COEREncodable[sequenceValues.size()]);
	}

	/**
	 * 
	 * @return the number of values in the sequence.
	 */
	public int size(){
		return sequenceValues.length;
	}

	/**
	 * 
	 * @return returns the array of sequence values.
	 */
	public COEREncodable[] getSequenceValues(){
		return sequenceValues;
	}

	/**
	 * 
	 * @return returns the sequence values as a list.
	 */
	public List<COEREncodable> getSequenceValuesAsList(){
		if(sequenceValues == null){
			return null;
		}
		List<COEREncodable> retval = new ArrayList<COEREncodable>(sequenceValues.length);
		for(COEREncodable next: sequenceValues){
			retval.add(next);
		}
		return retval;
	}

	@Override
	public void encode(DataOutputStream out) throws IOException {
		COERInteger length = new COERInteger(BigInteger.valueOf(sequenceValues.length), BigInteger.ZERO, null);
		length.encode(out);
		for(COEREncodable encodable : sequenceValues){
			encodable.encode(out);
		}
	}

	@Override
	public void decode(DataInputStream in) throws IOException {
		COERInteger length = new COERInteger(BigInteger.ZERO, null);
		length.decode(in);
		int sequenceSize = (int) length.getValueAsLong();
		sequenceValues = new COEREncodable[sequenceSize];
		for(int i=0;i<sequenceSize;i++){
			sequenceValues[i] = cloneEmptyValue();
			sequenceValues[i].decode(in);
		}
	}



	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(sequenceValues);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		COERSequenceOf other = (COERSequenceOf) obj;
		if (!Arrays.equals(sequenceValues, other.sequenceValues))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "COERSequenceOf [sequenceValues="
				+ Arrays.toString(sequenceValues) + "]";
	}

	private COEREncodable cloneEmptyValue() throws IOException {
		return COEREncodeHelper.deserialize(emptyValueEncoded);
	}

}
