package br.ufsc.labsec.pbad.hiring.criptografia.certificado;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.security.Security;

/**
 * Classe responsável por escrever um certificado no disco.
 */
public class EscritorDeCertificados {

    /**
     * Escreve o certificado indicado no disco.
     *
     * @param nomeArquivo           caminho que será escrito o certificado.
     * @param certificadoCodificado bytes do certificado.
     */
    public static void escreveCertificado(String nomeArquivo,
                                          byte[] certificadoCodificado,
                                          String descricao)
            throws IOException {

        PemObject pemObject = new PemObject(descricao, certificadoCodificado);

        try (PemWriter pemWriter = new PemWriter(new OutputStreamWriter(new FileOutputStream(nomeArquivo)))) {
            pemWriter.writeObject(pemObject);
        }
    }
}
