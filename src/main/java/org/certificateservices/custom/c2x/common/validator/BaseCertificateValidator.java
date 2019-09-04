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
package org.certificateservices.custom.c2x.common.validator;

import org.certificateservices.custom.c2x.common.Certificate;

/**
 * TODO
 */
public abstract class BaseCertificateValidator {

    /**
     * Method to cast given certificate to ieee1609dot2 or throw IllegalArgumentException
     * if certificate is of wrong type.
     * @param certificateChain the certificate chain to cast to ieee1609dot2
     * @return ieee1609dot2 variant of the certificate
     * @throws IllegalArgumentException
     */
    public static org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate[] toIEEE1609Certificates(Certificate[] certificateChain) throws IllegalArgumentException{
        org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate[] retval = new org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate[certificateChain.length];
        for(int i=0; i<certificateChain.length;i++){
            if(certificateChain[i] instanceof org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate){
                retval[i] = (org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate) certificateChain[i];
            }else {
                throw new IllegalArgumentException("Invalid certificate type: " + certificateChain[i].getClass().getName() + " expected of type " + org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate.class.getName());
            }
        }
        return retval;
    }


}
