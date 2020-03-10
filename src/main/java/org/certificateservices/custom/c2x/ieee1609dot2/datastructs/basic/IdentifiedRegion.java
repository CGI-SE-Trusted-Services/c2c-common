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

import java.io.IOException;

import org.certificateservices.custom.c2x.asn1.coer.COERChoice;
import org.certificateservices.custom.c2x.asn1.coer.COERChoiceEnumeration;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodable;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;

/**
 * This type indicates the region of validity of a certificate using region identifiers.
 * <p>
 * <b>Critical information fields</b>If present, this is a critical information field as defined in 5.2.5. An
 * implementation that does not recognize the indicated CHOICE when verifying a signed SPDU shall indicate that the
 * signed SPDU is invalid.
 * </p>
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class IdentifiedRegion extends COERChoice {
	
	private static final long serialVersionUID = 1L;
	
	public enum IdentifiedRegionChoices implements COERChoiceEnumeration{
		countryOnly(new CountryOnly()),
		countryAndRegions(new CountryAndRegions()),
		countryAndSubregions(new CountryAndSubregions());		

		private byte[] emptyCOEREncodable;
		private IdentifiedRegionChoices(COEREncodable emptyCOEREncodable){
			try {
				this.emptyCOEREncodable = COEREncodeHelper.serialize(emptyCOEREncodable);
			}catch (IOException e){
				throw new RuntimeException(e.getMessage(),e);
			}
		}
		
		@Override
		public COEREncodable getEmptyCOEREncodable() throws IOException {
			return COEREncodeHelper.deserialize(emptyCOEREncodable);
		}

		/**
		 * @return always false, no extension exists.
		 */
		@Override
		public boolean isExtension() {
			return false;
		}
	}
	
	/**
	 * Constructor used when encoding.
	 */
	public IdentifiedRegion(IdentifiedRegionChoices choice, COEREncodable value) {
		super(choice, value);
	}

	/**
	 * Constructor used when decoding.
	 */
	public IdentifiedRegion() {
		super(IdentifiedRegionChoices.class);
	}
	

	
	/**
	 * Returns type of identified region, one of IdentifiedRegionChoices enumeration.
	 */
	public IdentifiedRegionChoices getType(){
		return (IdentifiedRegionChoices) choice;
	}
	

	@Override
	public String toString() {
		return "IdentifiedRegion [" + value + "]";
	}
	
}
