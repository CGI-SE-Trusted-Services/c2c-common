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
import org.certificateservices.custom.c2x.asn1.coer.COERNull;

/**
 * This structure identifies the SSPs associated with a PSID for which the holder may issue or request certificates.
 * <p>
 *     <b>Consistency with issuing certificate.</b>If a certificate has a PsidSspRange A for which the ssp field is
 *     opaque, A is consistent with the issuing certificate if the issuing certificate contains one of the following:
 *     <ul>
 *         <li>(OPTION 1) A SubjectPermissions field indicating the choice all and no PsidSspRange field
 * containing the psid field in A;</li>
 *         <li>(OPTION 2) a PsidSspRange P for which the following holds:
 *         <ul>
 *             <li>The psid field in P is equal to the psid field in A and one of the following is true:
 *             <ul>
 *                 <li>The sspRange field in P indicates all.</li>
 *                 <li>The sspRange field in P indicates opaque, and the sspRange field in A indicates
 *                     opaque, and every OCTET STRING within the opaque in A is a duplicate of an
 *                     OCTET STRING within the opaque in P.</li>
 *             </ul>
 *             </li>
 *         </ul>
 *         </li>
 *     </ul>
 * </p>
 * <p>
 *     If a certificate has a PsidSspRange A for which the ssp field is all, A is consistent with the issuing
 *    certificate if the issuing certificate contains a PsidSspRange P for which the following holds:
 *    <ul>
 *      <li>(OPTION 1) A SubjectPermissions field indicating the choice all and no PsidSspRange field
 * containing the psid field in A;</li>
 *      <li>(OPTION 2) A PsidSspRange P for which the psid field in P is equal to the psid field in A and
 * the sspRange field in P indicates all.</li>
 *    </ul>
 * </p>
 * <p>
 *     For consistency rules for other types of SspRange, see the following subclauses.
 * </p>
 * <p>
 *     NOTE—The choice "all" may also be indicated by omitting the SspRange in the enclosing PsidSspRange structure.
 * Omitting the SspRange is preferred to explicitly indicating "all".
 * </p>
 *
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class SspRange extends COERChoice {
	
	private static final long serialVersionUID = 1L;
	
	public enum SspRangeChoices implements COERChoiceEnumeration{
		opaque(SequenceOfOctetString.class, false),
		all(COERNull.class,false),
		bitmapSspRange(BitmapSspRange.class,true);

		private boolean extension;
		private Class<COEREncodable> emptyCOEREncodable;

		SspRangeChoices(Class<?> emptyCOEREncodable, boolean extension){
			this.emptyCOEREncodable = (Class<COEREncodable>) emptyCOEREncodable;
			this.extension = extension;
		}

		@Override
		public COEREncodable getEmptyCOEREncodable() throws IOException {
			try{
				return emptyCOEREncodable.newInstance();
			}catch (Exception e){
				throw new IOException("Problems creating instance of type " + emptyCOEREncodable.getName() + ", message: " + e.getMessage(),e);
			}
		}

		/**
		 * @return true if this entry is an extension or false if  regular choice
		 */
		@Override
		public boolean isExtension() {
			return extension;
		}


	}

	/**
	 * Constructor that can be used if choice have value 'all', otherwise should data specific constructor be used.
	 * @param choice type of SspRange
	 */
	public SspRange(SspRangeChoices choice) {
		super(choice, new COERNull());
	}
	
	/**
	 * Constructor used when encoding of type
	 * @param choice type of SspRange
	 * @param data SequenceOfOctetString used if type is opaque, BitmapSspRange if type is bitmapSspRange, otherwise use null.
	 */
	public SspRange(SspRangeChoices choice, COEREncodable data) throws IOException{
		super(choice, (data != null? data : new COERNull()));
		if(choice == SspRangeChoices.all && data != null){
			throw new IOException("Invalid SspRange, if choice is all must related data be null.");
		}
		if(choice == SspRangeChoices.opaque && !(data instanceof SequenceOfOctetString)){
			throw new IOException("Invalid SspRange, if choice is opaque must related data be of type SequenceOfOctetString.");
		}
		if(choice == SspRangeChoices.bitmapSspRange && !(data instanceof BitmapSspRange)){
			throw new IOException("Invalid SspRange, if choice is bitmapSspRange must related data be of type BitmapSspRange.");
		}
	}

	/**
	 * Constructor used when decoding.
	 */
	public SspRange() {
		super(SspRangeChoices.class);
	}

	
	/**
	 * Returns type of identified region, one of SspRangeChoices enumeration.
	 */
	public SspRangeChoices getType(){
		return (SspRangeChoices) choice;
	}
	
	/**
	 * Returns the data if type is opaque, otherwise null.
	 */
	public SequenceOfOctetString getOpaqueData(){
		if(getType() == SspRangeChoices.opaque){
			return ((SequenceOfOctetString) getValue());
		}
		return null;
	}

	/**
	 * Returns the data if type is opaque, otherwise null.
	 */
	public BitmapSspRange getBitmapSspRange(){
		if(getType() == SspRangeChoices.bitmapSspRange){
			return ((BitmapSspRange) getValue());
		}
		return null;
	}
	

	@Override
	public String toString() {
		if(choice == SspRangeChoices.opaque){
			return "SspRange [" + choice + "=[" + getValue().toString().replaceAll("SequenceOfOctetString ", "") + "]]";	
		}
		if(choice == SspRangeChoices.bitmapSspRange){
			return "SspRange [" + choice + "=[" + getValue().toString().replaceAll("BitmapSspRange ", "") + "]]";
		}
		return "SspRange [" + choice + "]";
	}
	
}
