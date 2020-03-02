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
package org.certificateservices.custom.c2x.etsits102941.v131.util;

import org.certificateservices.custom.c2x.common.validator.CertificateRevokedException;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.messagesca.EtsiTs102941Data;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.*;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Opaque;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateId;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Data;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignedData;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static org.certificateservices.custom.c2x.etsits102941.v131.datastructs.messagesca.EtsiTs102941DataContent.EtsiTs102941DataContentChoices.*;
import static org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.CtlEntry.CtlEntryChoices.*;

/**
 * Utility class used to fetch information from a CTL such a ca certificate
 * from its name and its distribution centre URLs.
 */
public class Etsi102941CRLHelper {

    /**
     * Method that checks if a given certificateId is included in the CRLs toBeSigned Data.
     * @param toBeSignedCrl the CRL Content to check if given certificateId is included
     * @param certificateId the certificateId to check if it is included.
     * @throws CertificateRevokedException if given certificate id was found in list.
     */
    public void checkRevoked(ToBeSignedCrl toBeSignedCrl , HashedId8 certificateId) throws CertificateRevokedException {
        for(CrlEntry crlEntry : toBeSignedCrl.getEntries()){
            if(crlEntry.equals(certificateId)){
                throw new CertificateRevokedException("Certificate " + certificateId + " is included in CRL.");
            }
        }
    }

    /**
     * Help method to fetch the inner CRL data structure from the CRL.
     * @param etsiTs102941CRL the CTL to parse.
     * @return the ctlFormat object of the inner EtsiTs102941Data.
     * @throws IOException if decoding problems occurred.
     */
    public ToBeSignedCrl getToBeSignedCrl(EtsiTs102941CRL etsiTs102941CRL) throws IOException{
        Ieee1609Dot2Data innerData = ((SignedData) etsiTs102941CRL.getContent().getValue()).getTbsData().getPayload().getData();
        Opaque opaque = (Opaque) innerData.getContent().getValue();
        EtsiTs102941Data toBeSignedCtl = new EtsiTs102941Data(opaque.getData());
        if(toBeSignedCtl.getContent().getType() == certificateRevocationList){
            return toBeSignedCtl.getContent().getToBeSignedCrl();
        }
        throw new IOException("Invalid data structure, verify that data is of type certificateRevocationList.");
    }

}
