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
package org.certificateservices.custom.c2x.common.crypto;

/**
 * Interface that all cryptograpic key algorithms enumerations should implement in order
 * to be used with the CryptoManager
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public interface AlgorithmIndicator {
	
	Algorithm getAlgorithm();

}
