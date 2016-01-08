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
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;


/**
 * COER encoding of a Sequence, supports basic sequence of required, optional and default fields.
 * <p>
 * To create a sequence for create it with a given size, then construct it by adding fields, it's later possible to set values of fields at  given position.
 * 
 * <b>Important, currently is not extensions supported</b>
 * <p>
 * For more information see ISO/IEC 8825-7:2015 Section 16
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

public class COERSequence extends COEREncodable {
	
	private static final long serialVersionUID = 1L;
	
	public static final COEREncodable NO_DEFAULT = null;
	
	boolean hasExtension;
	List<Field> sequenceValues;
	
	/**
	 * Constructor used for both encoding and decoding.
	 * @param hasExtension if the sequence has extensions (currently not supported).
	 * @param size the size of the final sequence, (i.e number of fields, both required and optional, not only number of set fields)
	 */
	public COERSequence(boolean hasExtension, int size){
		this.hasExtension = hasExtension;
		sequenceValues = new ArrayList<Field>(size);
	}
	
	/**
	 * Constructor used for both encoding and decoding.
	 * @param hasExtension if the sequence has extensions (currently not supported).
	 */
	public COERSequence(boolean hasExtension){
		this.hasExtension = hasExtension;
		sequenceValues = new ArrayList<Field>();
	}

	/**
	 * Adds a field to the sequence structure when the value is currently not known.
	 * 
	 * @param position the position of the field.
	 * @param optional true if this field is optional or required
	 * @param emptyValue empty version of the COEREncodable containing the constraints but no value. (Required)
	 * @param defaultValue default value if fields is optional but no value is set. (Optional, use NO_DEFAULT for no default value)
	 */
	public void addField(int position,  boolean optional, COEREncodable emptyValue, COEREncodable defaultValue){
		sequenceValues.add(position,new Field(null, optional, emptyValue, defaultValue));
	}
	
	/**
	 * Adds a field to the sequence structure when the value is  known.
	 * 
	 * @param position the position of the field.
	 * @param value the COER encodable value to set. (Optional, use null if no value should be set).
	 * @param optional true if this field is optional or required
	 * @param emptyValue empty version of the COEREncodable containing the constraints but no value. (Required)
	 * @param defaultValue default value if fields is optional but no value is set. (Optional, use NO_DEFAULT for no default value)
	 */
	public void addField(int position, COEREncodable value, boolean optional, COEREncodable emptyValue, COEREncodable defaultValue){
		sequenceValues.add(position,new Field(value, optional, emptyValue, defaultValue));
	}
	
	/**
	 * 
	 * @return the size of this sequence.
	 */
	public int size(){
		return sequenceValues.size();
	}
	
	/**
	 * Method to set the value at a given position in the COER Sequence.
	 * @param position position to set the value at.
	 * @param value the value to set.
	 */
	public void set(int position, COEREncodable value){
		Field f = sequenceValues.get(position);
		if(f==null){
			throw new IllegalArgumentException("Error no field exist for COER sequence with position " + position);
		}
		f.value = value;
	}
	
	/**
	 * Method that retrieves the value at a given position, if optional and default value is set it will be returned if no value exists at given position, otherwise null.
	 */
	public COEREncodable get(int position){
		Field f = sequenceValues.get(position);
		if(f.value == null){
			return f.defaultValue;
		}
		return f.value;
	}
	
	/**
	 * @return if the sequence has extensions (currently not supported).
	 */
	public boolean getHasExtension(){
		return hasExtension;
	}
	


	@Override
	public void encode(DataOutputStream out) throws IOException {
		if(hasExtension){
			throw new IOException("Support for COER Sequence extensions is currently not supported");
		}
		
		writePreAmple(out);
		for(Field f : sequenceValues){
			if(f.value != null){
				f.value.encode(out);
			}else{
				if(!f.optional){
					throw new IOException("Error encoding COER Sequence, one non optional field was null");
				}
			}
		}
		
		// Extensitons here
	}


	private void writePreAmple(DataOutputStream out) throws IOException {
		
		List<Field> optionalFields = getOptionalFields();
		if(hasExtension || optionalFields.size() > 0){
			long preamble = hasExtension ? 1:0;
			for(Field optionalField : optionalFields){
				preamble = preamble << 1;
				if(optionalField.value != null){
					preamble++;
				}
			}

			COERBitString bitString = new COERBitString(preamble, optionalFields.size() + 1, true);
			bitString.encode(out);
		}
	}


	@Override
	public void decode(DataInputStream in) throws IOException {
		List<Field> optionalFields = getOptionalFields();
		long preAmple = readPreAmple(in, optionalFields);
		for(int i=optionalFields.size()-1; i>=0; i--){
			Field f = optionalFields.get(i);
			f.exists = (preAmple % 2 == 1);
			preAmple = preAmple >>> 1;
		}
		hasExtension = (preAmple % 2 == 1);
		if(hasExtension){
			throw new IOException("Support for COER Sequence extensions is currently not supported");
		}
		
		for(Field f : sequenceValues){
			if(!f.optional || f.exists){
				f.emptyValue.decode(in);
				f.value = f.emptyValue;
			}
		}
		
		// Extensitons here
	}
	
	public long readPreAmple(DataInputStream in, List<Field> optionalFields) throws IOException {
		if(hasExtension || optionalFields.size() > 0){
			COERBitString bitString = new COERBitString(optionalFields.size() +1);
			bitString.decode(in);
			return bitString.getBitString();
		}else{
			return 0;
		}
	}
	
	private List<Field> getOptionalFields(){
		List<Field> retval = new ArrayList<Field>();
		for(Field f : sequenceValues){
			if(f.optional){
				retval.add(f);
			}
		}
		return retval;
	}
	
	private class Field implements Serializable{
		

		private static final long serialVersionUID = 1L;
		
		private Field(COEREncodable value, boolean optional, COEREncodable emptyValue, COEREncodable defaultValue){
			this.value = value;
			this.optional = optional;
			this.defaultValue = defaultValue;
			this.emptyValue = emptyValue;
		}
		
		boolean exists=false;
		COEREncodable value; 
		boolean optional; 
		COEREncodable defaultValue;
		COEREncodable emptyValue;
		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result
					+ ((defaultValue == null) ? 0 : defaultValue.hashCode());
			result = prime * result
					+ ((emptyValue == null) ? 0 : emptyValue.hashCode());
			result = prime * result + (optional ? 1231 : 1237);
			result = prime * result + ((value == null) ? 0 : value.hashCode());
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
			Field other = (Field) obj;
			if (defaultValue == null) {
				if (other.defaultValue != null)
					return false;
			} else if (!defaultValue.equals(other.defaultValue))
				return false;
			if (emptyValue == null) {
				if (other.emptyValue != null)
					return false;
			} else if (!emptyValue.getClass().equals(other.emptyValue.getClass()))
				return false;
			if (optional != other.optional)
				return false;
			if (value == null) {
				if (other.value != null)
					return false;
			} else if (!value.equals(other.value))
				return false;
			return true;
		}

	}
	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + (hasExtension ? 1231 : 1237);
		result = prime * result
				+ ((sequenceValues == null) ? 0 : sequenceValues.hashCode());
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
		COERSequence other = (COERSequence) obj;
		if (hasExtension != other.hasExtension)
			return false;
		if (sequenceValues == null) {
			if (other.sequenceValues != null)
				return false;
		} else if (!sequenceValues.equals(other.sequenceValues))
			return false;
		return true;
	}


	@Override
	public String toString() {
		String sequenceValueString = "";
		for(int i=0;i<size();i++){
			if(get(i) != null){
			  sequenceValueString += get(i).toString() + (i== size()-1?"":", ");
			}else{
				sequenceValueString += (i== size()-1?"NULL":"NULL, ");
			}
		}
		
		return "COERSequence [hasExtension=" + hasExtension
				+ ", [" + sequenceValueString + "]]";
	}
	
	
}
