/************************************************************************
 *                                                                       *
3 *  Certificate Service -  Car2Car Core                                  *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Affero General Public License   *
 *  License as published by the Free Software Foundation; either         *
 *  version 3   of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic;

import java.io.IOException;

import org.certificateservices.custom.c2x.asn1.coer.COERChoice;
import org.certificateservices.custom.c2x.asn1.coer.COERChoiceEnumeration;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodable;

/**
 * This data structure defines the typeSpecific structure in CrlContents.
 * 
 * <li>fullHashCrl contains a full hash-based CRL, i.e. a listing of the hashes of all certificates that:
 * contain the indicated cracaId and crlSeries values, and are revoked by hash, and have been revoked, and 
 * have not expired.
 * <li>deltaHashCrl contains a delta hash-based CRL, i.e. a listing of the hashes of all certificates that
 * contain the specified cracaId and crlSeries values, and
 * are revoked by hash, and have been revoked since the previous CRL that contained the indicated cracaId 
 * and crlSeries values.
 * <li>fullLinkedCrl contains a full linkage ID-based CRL, i.e. a listing of the individual and/or group 
 * linkage data for all certificates that contain the indicated cracaId and crlSeries values, and are revoked 
 * by linkage data, and have been revoked, and have not expired.
 * <li>deltaLinkedCrl contains a delta linkage ID-based CRL, i.e. a listing of the individual and/or group 
 * linkage data for all certificates that contain the specified cracaId and crlSeries values, and are revoked 
 * by linkage data, and have been revoked since the previous CRL that contained the indicated cracaId and 
 * crlSeries values.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class CrlContentsType extends COERChoice {
	
	
	private static final long serialVersionUID = 1L;
	
	public enum CrlContentsTypeChoices implements COERChoiceEnumeration{
		fullHashCrl,
		deltaHashCrl,
		fullLinkedCrl,
		deltaLinkedCrl;

		@Override
		public COEREncodable getEmptyCOEREncodable() throws IOException {
	      switch (this) {
		case fullHashCrl:
		case deltaHashCrl:
			return new ToBeSignedHashIdCrl();
		case fullLinkedCrl:
		case deltaLinkedCrl:
		default:
			return new ToBeSignedLinkageValueCrl();
		}
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
	 * Constructor used when encoding of type fullHashCrl or fullHashCrl
	 */
	public CrlContentsType(CrlContentsTypeChoices type, ToBeSignedHashIdCrl value) {
		super(type, value);
	}
	
	/**
	 * Constructor used when encoding of type fullLinkedCrl or deltaLinkedCrl
	 */
	public CrlContentsType(CrlContentsTypeChoices type, ToBeSignedLinkageValueCrl value) {
		super(type, value);
	}
	

	/**
	 * Constructor used when decoding
	 */
	public CrlContentsType() {
		super(CrlContentsTypeChoices.class);
	}
		
	/**
	 * Returns the type of crl.
	 */
	public CrlContentsTypeChoices getType(){
		return (CrlContentsTypeChoices) choice;
	}

	@Override
	public String toString() {
	      switch (getType()) {
		case fullHashCrl:
		case deltaHashCrl:
			return "CrlContentsType [" + choice + "=" + value.toString().replace("ToBeSignedHashIdCrl ", "") +"]";
		case fullLinkedCrl:
		case deltaLinkedCrl:
		default:
			return "CrlContentsType [" + choice + "=" + value.toString().replace("ToBeSignedLinkageValueCrl ", "") +"]";
		}
	}
	
}
