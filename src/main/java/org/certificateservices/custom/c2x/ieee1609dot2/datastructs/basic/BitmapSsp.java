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

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * This structure represents a bitmap representation of a SSP. The mapping of the bits of the bitmap to
 * constraints on the signed SPDU is PSID-specific.
 * <p>
 * <b>Consistency with issuing certificate.</b>If a certificate has an appPermissions entry A for which the ssp field is bitmapSsp, A is consistent
 * with the issuing certificate if the issuing certificate contains one of the following:
 * <ul>
 *     <li>(OPTION 1) A SubjectPermissions field indicating the choice all and no PsidSspRange field
 * containing the psid field in A;</li>
 *     <li>(OPTION 2) A PsidSspRange P for which the following holds:
 *       <ul>
 *           <li>The psid field in P is equal to the psid field in A and one of the following is true:
 *           <ul>
 *               <li>EITHER The sspRange field in P indicates all</li>
 *               <li>OR The sspRange field in P indicates bitmapSspRange and for every bit set to 1
 * in the sspBitmask in P, the bit in the identical position in the sspValue in A is set
 * equal to the bit in that position in the sspValue in P.</li>
 *           </ul>
 *           </li>
 *       </ul>
 *
 *     </li>
 * </ul>
 * </p>
 * <p>
 * NOTE—A BitmapSsp B is consistent with a BitmapSspRange R if for every bit set to 1 in the sspBitmask in
 * R, the bit in the identical position in B is set equal to the bit in that position in the sspValue in R. For each bit set to 0
 * in the sspBitmask in R, the corresponding bit in the identical position in B may be freely set to 0 or 1, i.e., if a bit is
 * set to 0 in the sspBitmask in R, the value of corresponding bit in the identical position in B has no bearing on
 * whether B and R are consistent.
 * </p>
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class BitmapSsp extends COEROctetStream {

	private static final int OCTETSTRING_MIN_SIZE = 0;
	private static final int OCTETSTRING_MAX_SIZE = 31;

	private static final long serialVersionUID = 1L;


	/**
	 * Constructor used when decoding
	 */
	public BitmapSsp(){
		super(OCTETSTRING_MIN_SIZE, OCTETSTRING_MAX_SIZE);
	}

	/**
	 * Constructor of Bitmap data.
     *
	 * @param data the bitmapSpp data.
	 * @throws IOException if supplied arguments where invalid.
	 */
	public BitmapSsp(byte[] data) throws IOException {
		super(data,OCTETSTRING_MIN_SIZE, OCTETSTRING_MAX_SIZE);

	}

	@Override
	public String toString() {
		return "BitmapSsp [" + Hex.toHexString(data) + "]";
	}

}
