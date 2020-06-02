package org.certificateservices.custom.c2x.ieee1609dot2.generator;

import org.certificateservices.custom.c2x.common.BadArgumentException;
import org.certificateservices.custom.c2x.common.CertStore;
import org.certificateservices.custom.c2x.common.MapCertStore;
import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;
import org.certificateservices.custom.c2x.common.crypto.CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.Receiver;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

/**
 * Utility class with helper method to build CertStores and Receiver stores.
 */
public class StoreBuilder {

    /**
     * Method to build a map of HashedId8 to Certificate from a collection of certificates.
     * @param certificates the collection of certificate to build store of.
     * @return a map of HashedId8 to certificate.
     */
    public static Map<HashedId8, org.certificateservices.custom.c2x.common.Certificate>  buildCertMap(CryptoManager cryptoManager, Collection<Certificate> certificates) throws BadArgumentException, NoSuchAlgorithmException, IOException {
        Map<HashedId8, org.certificateservices.custom.c2x.common.Certificate> retval = new HashMap<>();
        for(Certificate cert : certificates){
            // Implicit certificate only supports ECDSA 256 since the reconstruction value is of type ECP256CurvePoint.
            AlgorithmIndicator alg = cert.getSignature() != null ? cert.getSignature().getType() : HashAlgorithm.sha256;
            retval.put(new HashedId8(cryptoManager.digest(cert.getEncoded(), alg)), cert);
        }

        return retval;
    }

    /**
     * Method to build a cert store map of HashedId8 to Certificate from a collection of certificates.
     * @param certificates the collection of certificate to build store of.
     * @return a map of HashedId8 to certificate.
     */
    public static CertStore buildCertStore(CryptoManager cryptoManager, Collection<Certificate> certificates) throws BadArgumentException, NoSuchAlgorithmException, IOException {
        return new MapCertStore(buildCertMap(cryptoManager, certificates));
    }

    /**
     * Method to build a cert store map of HashedId8 to Certificate from an array of certificates.
     * @param certificates the array of certificate to build store of.
     * @return a map of HashedId8 to certificate.
     */
    public static CertStore buildCertStore(CryptoManager cryptoManager, Certificate[] certificates) throws BadArgumentException, NoSuchAlgorithmException, IOException{
        return buildCertStore(cryptoManager, Arrays.asList(certificates));
    }

    /**
     * Method to build a store of receiver in order of a hashedId8 -> Receiver
     *
     * @param receivers collection of receivers to build map of.
     * @return a map of hashedId8 -> receiver
     */
    public static Map<HashedId8, Receiver> buildReceiverStore(CryptoManager cryptoManager,Collection<Receiver> receivers) throws BadArgumentException, IOException, GeneralSecurityException {
        Map<HashedId8, Receiver> retval = new HashMap<>();
        for(Receiver r : receivers){
            retval.put(r.getReference(r.getHashAlgorithm(),cryptoManager), r);
        }

        return retval;
    }



    /**
     * Method to build a store of receiver in order of a hashedId8 -> Receiver map from an array.
     *
     * @param receivers array of receivers to build map of.
     * @return a map of hashedId8 -> Receivers
     */
    public static Map<HashedId8, Receiver> buildReceiverStore(CryptoManager cryptoManager,Receiver[] receivers) throws BadArgumentException, GeneralSecurityException, IOException{
        return buildReceiverStore(cryptoManager, Arrays.asList(receivers));
    }
}
