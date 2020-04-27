package org.certificateservices.custom.c2x.common;

import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;

import java.util.Map;

/**
 * Implementation of CertStore with an underlying Map of HashedId8 to Certificate.
 *
 * @author Philip Vendil 2020-04-24
 */
public class MapCertStore implements CertStore {

    private Map<HashedId8, ? extends Certificate> map;


    /**
     * Default Constructor.
     * @param map the underlying map of certificates.
     */
    public MapCertStore(Map<HashedId8, ? extends Certificate> map){
        this.map = map;
    }

    /**
     * Main method to fetch a certificate from the store using the hashedId.
     *
     * @param hashedId the hasdedId8 value of the certificate.
     * @return the related certificate or null if not found.
     */
    @Override
    public Certificate get(HashedId8 hashedId) {
        return map.get(hashedId);
    }
}
