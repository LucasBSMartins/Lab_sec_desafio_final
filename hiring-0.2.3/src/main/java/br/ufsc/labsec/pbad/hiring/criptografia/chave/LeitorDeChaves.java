package br.ufsc.labsec.pbad.hiring.criptografia.chave;

import org.bouncycastle.util.io.pem.PemReader;

import java.io.FileReader;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
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

            // Lê o conteúdo do objeto Pem do arquivo e o transforma em uma PKCS8EncodedKeySpec
            PKCS8EncodedKeySpec keySpecs = new PKCS8EncodedKeySpec(pemReader.readPemObject().getContent());

            // Retorna uma chave privada a partir das especificações da chave
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

        // Lê o conteúdo do objeto Pem do arquivo e o transforma em uma X509EncodedKeySpec
        X509EncodedKeySpec keySpecs = new X509EncodedKeySpec(pemReader.readPemObject().getContent());

        // Retorna uma instância da chave pública a partir das especificações da chave
        return KeyFactory.getInstance(algoritmo).generatePublic(keySpecs);

    } catch ( IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
            return null;
    }
}
