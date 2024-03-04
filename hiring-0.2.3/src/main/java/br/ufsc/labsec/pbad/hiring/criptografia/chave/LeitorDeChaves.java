package br.ufsc.labsec.pbad.hiring.criptografia.chave;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.FileReader;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;


/**
 * Classe responsável por ler uma chave assimétrica do disco.
 *
 * @see KeyFactory
 * @see KeySpec
 */
public class LeitorDeChaves {

    /**
     * Lê a chave privada do local indicado.
     *
     * @param caminhoChave local do arquivo da chave privada.
     * @param algoritmo    algoritmo de criptografia assimétrica que a chave
     *                     foi gerada.
     * @return Chave privada.
     */
    public static PrivateKey lerChavePrivadaDoDisco(String caminhoChave,
                                                    String algoritmo) {
        try (FileReader fileReader = new FileReader(caminhoChave);
             PemReader pemReader = new PemReader(fileReader)) {

            PKCS8EncodedKeySpec keySpecs = new PKCS8EncodedKeySpec(pemReader.readPemObject().getContent());
            return KeyFactory.getInstance(algoritmo).generatePrivate(keySpecs);

        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Lê a chave pública do local indicado.
     *
     * @param caminhoChave local do arquivo da chave pública.
     * @param algoritmo    algoritmo de criptografia assimétrica que a chave
     *                     foi gerada.
     * @return Chave pública.
     */
    public static PublicKey lerChavePublicaDoDisco(String caminhoChave,
                                                   String algoritmo) {

    try (FileReader fileReader = new FileReader(caminhoChave);
        PemReader pemReader = new PemReader(fileReader)) {

        KeyFactory factory = KeyFactory.getInstance(algoritmo);
        PemObject pemObject = pemReader.readPemObject();
        byte[] content = pemObject.getContent();
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(content);
        return factory.generatePublic(pubKeySpec);

        } catch ( IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
            return null;
    }
}
