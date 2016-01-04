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

/**
 * COER encoding of a Choice, containing a tag and a value.
 * <p> 
 * For more information see ISO/IEC 8825-7:2015 Section 20
 * <p>
 * An enum implementing the COERChouceEnumeration should be used in combination with this COERChoice.
 * 
 * @see COERChoiceEnumeration
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class COERChoice extends COEREncodable{
	
	private Class<?> choiceEnum;
	private COERChoiceEnumeration choice;
	private COEREncodable value;
	
	/**
	 * Constructor used when decoding a COER Choice.
	 * 
	 * @param choiceEnum the class of the enum that implements COERChoiceEnumeration
	 */
	public COERChoice(Class<?> choiceEnum){
		this.choiceEnum = choiceEnum;
	}
	
	/**
	 * Constructor used when encoding a COER Choice.
	 * 
	 * @param choice a enum value of an enumeration implementing COERChoiceEnumeration
	 * @param value the related value.
	 */
	public COERChoice(COERChoiceEnumeration choice, COEREncodable value){
		this.choice = choice;
		this.value = value;
	}

	/**
	 * 
	 * @return the related choice enum value.
	 */
	public COERChoiceEnumeration getChoice() {
		return choice;
	}

	/**
	 * 
	 * @return the related value to the choice.
	 */
	public COEREncodable getValue() {
		return value;
	}

	@Override
	public void encode(DataOutputStream out) throws IOException {
		COERTag tag = new COERTag(COERTag.CONTEXT_SPECIFIC_TAG_CLASS, choice.ordinal());
		tag.encode(out);
		value.encode(out);
	}

	@Override
	public void decode(DataInputStream in) throws IOException {
		COERTag tag = new COERTag();
		tag.decode(in);
		choice = (COERChoiceEnumeration) choiceEnum.getEnumConstants()[(int) tag.getTagNumber()];
	
		value = choice.getEmptyCOEREncodable();
		value.decode(in);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((choice == null) ? 0 : choice.hashCode());
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
		COERChoice other = (COERChoice) obj;
		if (choice == null) {
			if (other.choice != null)
				return false;
		} else if (!choice.equals(other.choice))
			return false;
		if (value == null) {
			if (other.value != null)
				return false;
		} else if (!value.equals(other.value))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "COERChoice [choice=" + choice + ", value=" + value + "]";
	}

}
