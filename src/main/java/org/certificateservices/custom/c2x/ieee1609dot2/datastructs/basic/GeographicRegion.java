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
import java.util.List;

import org.certificateservices.custom.c2x.asn1.coer.COERChoice;
import org.certificateservices.custom.c2x.asn1.coer.COERChoiceEnumeration;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodable;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.IdentifiedRegion.IdentifiedRegionChoices;

/**
 * This type represents a geographic region of a specified form.
 * 
 * <li>rectangularRegion - is an array of RectangularRegion structures containing at least one entry. This field is interpreted as a series of rectangles, which may overlap or be
 * disjoint. The permitted region is any point within any of the rectangles.
 * <li>circularRegion or polygonalRegion - contain a single instance of their respective types.
 * <li>identifiedRegion -  is an array of IdentifiedRegion structures containing at least one entry. The permitted region is any point within any of the identified regions.
 * <p>
 * A certificate is not valid if any part of the region indicated in its scope field lies outside the region indicated in the scope of its issuer.
 * <p>
 * <b>Critical information fields:</b>
 * <li>If present, this is a critical information field as defined in 5.2.5. An implementation that does not recognize the indicated CHOICE when verifying a 
 * signed SPDU shall indicate that the signed SPDU is invalid.
 * <li>If selected, rectangularRegion is a critical information field as defined in 5.2.5. An implementation that does not support the number of RectangularRegion 
 * in rectangularRegions when verifying a signed SPDU shall indicate that the signed SPDU is invalid. A compliant implementation shall support rectangularRegions 
 * fields containing at least eight entries.
 * <li>If selected, identifiedRegion is a critical information field as defined in 5.2.5. An implementation that does not support the number of IdentifiedRegion in 
 * identifiedRegion shall reject the signed SPDU as invalid. A compliant implementation shall support identifiedRegion fields containing at least eight entries.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class GeographicRegion extends COERChoice {
	
	private static final long serialVersionUID = 1L;
	
	public enum GeographicRegionChoices implements COERChoiceEnumeration{
		circularRegion(new CircularRegion()),
		rectangularRegion(new SequenceOfRectangularRegion()),
		polygonalRegion(new PolygonalRegion()),
		identifiedRegion(new SequenceOfIdentifiedRegion());

		private byte[] emptyCOEREncodable;

		GeographicRegionChoices(COEREncodable emptyCOEREncodable){
			try {
				this.emptyCOEREncodable = COEREncodeHelper.serialize(emptyCOEREncodable);
			}catch(IOException e){
				throw new RuntimeException("Error encoding geographic region: " + e.getMessage(),e);
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
	public GeographicRegion(GeographicRegionChoices choice, COEREncodable value) {
		super(choice, value);
	}

	/**
	 * Constructor used when decoding.
	 */
	public GeographicRegion() {
		super(GeographicRegionChoices.class);
	}

	
	/**
	 * Returns type of identified region, one of GeographicRegionChoices enumeration.
	 */
	public GeographicRegionChoices getType(){
		return (GeographicRegionChoices) choice;
	}
	

	@Override
	public String toString() {
		return "GeographicRegion [" + value + "]";
	}
	
	/**
	 * Help method to simply the generation of a GeographicRegion for a sequence of identified regions of a list of country only values
	 * @param identifiedCountries list of country only values used in the region.
	 * @return a generated geographic region. not null if list is null
	 */
	public static GeographicRegion generateRegionForCountrys(List<Integer> identifiedCountries){
		if(identifiedCountries == null){
			return null;
		}

		IdentifiedRegion[] idRegions = new IdentifiedRegion[identifiedCountries.size()];
		for(int i=0; i<identifiedCountries.size(); i++){
			Integer c = identifiedCountries.get(i);
			idRegions[i] = new IdentifiedRegion(IdentifiedRegionChoices.countryOnly, new CountryOnly(c));
		}
		return new GeographicRegion(GeographicRegionChoices.identifiedRegion, new SequenceOfIdentifiedRegion(idRegions));
	}
	
}
