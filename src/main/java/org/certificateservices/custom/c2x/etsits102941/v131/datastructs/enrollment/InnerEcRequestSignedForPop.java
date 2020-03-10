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
package org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment;

import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSigned;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Content;

import java.io.IOException;

/**
 * Class representing InnerAtRequest defined in ETSI TS 102 941 Enrollment Types.
 * <p>
 *     Extends EtsiTs103097DataSigned profile and the constructor doesn't just take a InnerEcRequest but
 *     the Ieee1609Dot2Content containing a Signed Data. Message should generally be generated using
 *     a generator class.
 * </p>
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class InnerEcRequestSignedForPop extends EtsiTs103097DataSigned {

	/**
	 * Constructor used when decoding
	 */
	public InnerEcRequestSignedForPop() {
	}

	/**
	 * Constructor used when encoding using default protocol version.
	 *
	 * @param content the Ieee1609Dot2Content of the SignedData not the actual InnerEcRequest.
	 * @throws IOException if encoded data was invalid according to ASN1 schema.
	 */
	public InnerEcRequestSignedForPop(Ieee1609Dot2Content content) throws IOException {
		super(content);
	}

	/**
	 * Constructor used when encoding
	 *
	 * @param protocolVersion the version of the message
	 * @param content the Ieee1609Dot2Content of the SignedData not the actual InnerEcRequest.
	 * @throws IOException if encoded data was invalid according to ASN1 schema.
	 */
	public InnerEcRequestSignedForPop(int protocolVersion, Ieee1609Dot2Content content) throws IOException {
		super(protocolVersion, content);
	}

	/**
	 * Constructor decoding a Ieee1609Dot2Data from an encoded byte array.
	 *
	 * @param encodedData byte array encoding of the Ieee1609Dot2Data.
	 * @throws IOException              if communication problems occurred during serialization.
	 */
	public InnerEcRequestSignedForPop(byte[] encodedData) throws IOException {
		super(encodedData);
	}

	@Override
    public String toString() {
        return super.toString().replace("EtsiTs103097DataSigned ", "InnerEcRequestSignedForPop ").replace("EtsiTs103097Data ", "InnerEcRequestSignedForPop ");
    }

}
