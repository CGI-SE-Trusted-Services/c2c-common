package org.certificateservices.custom.c2x.common;

import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;


/**
 * Interface defining a Certificate Store used to be a container of certificates.
 *
 * @author Philip Vendil 2020-04-13
 */
public interface CertStore {

    /**
     * Main method to fetch a certificate from the store using the hashedId.
     * @param hashedId the hasdedId8 value of the certificate.
     * @return the related certificate or null if not found.
     */
    Certificate get(HashedId8 hashedId);
}
