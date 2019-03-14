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

import org.certificateservices.custom.c2x.asn1.coer.COERChoice;
import org.certificateservices.custom.c2x.asn1.coer.COERChoiceEnumeration;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodable;

/**
 * Base class for both EccP256CurvePoint and EccP384CurvePoint.
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public abstract class EccCurvePoint extends COERChoice {


	private static final long serialVersionUID = 1L;

	/**
	 * Constructor used when decoding a COER Choice.
	 *
	 * @param choiceEnum the class of the enum that implements COERChoiceEnumeration
	 */
	public EccCurvePoint(Class<?> choiceEnum){
		super(choiceEnum);
	}

	/**
	 * Constructor used when encoding a COER Choice.
	 *
	 * @param choice a enum value of an enumeration implementing COERChoiceEnumeration
	 * @param value the related value.
	 */
	public EccCurvePoint(COERChoiceEnumeration choice, COEREncodable value){
		super(choice,value);
	}


}
