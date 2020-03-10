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
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;
import org.certificateservices.custom.c2x.asn1.coer.COERSequence;

import java.io.IOException;

/**
 * This structure represents a bitmap representation of a SSP. The sspValue indicates permissions. The
 * sspBitmask contains an octet string used to permit or constrain sspValue fields in issued certificates.
 * The sspValue and sspBitmask fields shall be of the same length.
 * <p>
 *     <b>Consistency with issuing certificate.</b>If a certificate has an PsidSspRange value P for which the sspRange
 *     field is bitmapSspRange, P is consistent with the issuing certificate if the issuing certificate contains one of
 *     the following:
 *     <ul>
 *         <li>(OPTION 1) A SubjectPermissions field indicating the choice all and no PsidSspRange field
 * containing the psid field in P;</li>
 *         <li>(OPTION 2) A PsidSspRange R for which the following holds:</li>
 *         <ul>
 *             <li>The psid field in R is equal to the psid field in P and one of the following is true:
 *             <ul>
 *                 <li>EITHER The sspRange field in R indicates all</li>
 *                 <li>OR The sspRange field in R indicates bitmapSspRange and for every bit set to 1
 * in the sspBitmask in R:
 *                 <ul>
 *                     <li>The bit in the identical position in the sspBitmask in P is set equal to 1, AND</li>
 *                     <li>The bit in the identical position in the sspValue in P is set equal to the bit in that
 * position in the sspValue in R.</li>
 *                 </ul>
 *                 </li>
 *             </ul>
 *             </li>
 *
 *         </ul>
 *     </ul>
 * </p>
 * <p>
 *     Reference ETSI TS 103 097 [B7] for more information on bitmask SSPs.
 * </p>
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class BitmapSspRange extends COERSequence {


	private static final long serialVersionUID = 1L;

	private static final int SSPVALUE = 0;
	private static final int SSPBITMASK = 1;

	/**
	 * Constructor used when decoding
	 */
	public BitmapSspRange(){
		super(false,2);
		init();
	}

	/**
	 * Constructor used when encoding
	 */
	public BitmapSspRange(byte[] sspValue, byte[] sspBitmask) throws IOException{
		super(false,2);
		if(sspValue == null){
			throw new IOException("Invalid argument: sspValue in BitmapSspRange cannot be null.");
		}
		if(sspBitmask == null){
			throw new IOException("Invalid argument: sspBitmask in BitmapSspRange cannot be null.");
		}
		init();
		set(SSPVALUE, new COEROctetStream(sspValue,1,32));
		set(SSPBITMASK, new COEROctetStream(sspBitmask,1,32));
	}

	/**
	 * 
	 * @return ssp value
	 */
	public byte[] getSspValue(){
		return ((COEROctetStream) get(SSPVALUE)).getData();
	}
	
	/**
	 * 
	 * @return the ssp bit mask
	 */
	public byte[] getSspBitMask(){
		return ((COEROctetStream) get(SSPBITMASK)).getData();
	}
	
	private void init(){
		addField(SSPVALUE, false, new COEROctetStream(1,32), null);
		addField(SSPBITMASK, false, new COEROctetStream(1,32), null);
	}
	
	@Override
	public String toString() {
		return "BitmapSspRange [sspValue=" + Hex.toHexString(getSspValue()) + ", sspBitmask=" + Hex.toHexString(getSspBitMask())+ "]";
	}
	
}
