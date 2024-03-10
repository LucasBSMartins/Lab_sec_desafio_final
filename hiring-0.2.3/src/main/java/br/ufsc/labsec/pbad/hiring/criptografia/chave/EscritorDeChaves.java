package br.ufsc.labsec.pbad.hiring.criptografia.chave;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.security.Key;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

/**
 * Essa classe é responsável por escrever uma chave assimétrica no disco. Note
 * que a chave pode ser tanto uma chave pública quanto uma chave privada.
 *
 * @see Key
 */
public class EscritorDeChaves {

    /**
     * Escreve uma chave no local indicado.
     *
     * @param chave         chave assimétrica a ser escrita em disco.
     * @param nomeDoArquivo nome do local onde será escrita a chave.
     */
    public static void escreveChaveEmDisco(Key chave, String nomeDoArquivo, String descricao)
            throws IOException {

        // Cria um objeto PemObject com a descrição e os bytes codificados da chave
        PemObject pemObject = new PemObject(descricao, chave.getEncoded());

        // Escreve o objeto Pem no arquivo especificado
        try (PemWriter pemWriter = new PemWriter(new OutputStreamWriter(new FileOutputStream(nomeDoArquivo)))) {
            pemWriter.writeObject(pemObject);
        }
    }
}
