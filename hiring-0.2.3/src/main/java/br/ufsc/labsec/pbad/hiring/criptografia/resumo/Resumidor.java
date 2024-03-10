package br.ufsc.labsec.pbad.hiring.criptografia.resumo;
import br.ufsc.labsec.pbad.hiring.Constantes;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Classe responsável por executar a função de resumo criptográfico.
 *
 * @see MessageDigest
 */
public class Resumidor {

    private MessageDigest md;
    private String algoritmo;

    /**
     * Construtor.
     */
    public Resumidor() throws NoSuchAlgorithmException{
        // Pega o tipo de algoritmo usado,"SHA-256" neste caso
        this.algoritmo = Constantes.algoritmoResumo;
        this.md = MessageDigest.getInstance(this.algoritmo);
    }

    /**
     * Calcula o resumo criptográfico do arquivo indicado.
     *
     * @param arquivoDeEntrada arquivo a ser processado.
     * @return Bytes do resumo.
     */
    public byte[] resumir(File arquivoDeEntrada)  throws IOException {

        byte[] bytes = Files.readAllBytes(arquivoDeEntrada.toPath());

        return md.digest(bytes);
    }

    /**
     * Escreve o resumo criptográfico no local indicado.
     *
     * @param resumo         resumo criptográfico em bytes.
     * @param caminhoArquivo caminho do arquivo.
     */
    public void escreveResumoEmDisco(byte[] resumo, String caminhoArquivo) {
        
        try (FileOutputStream fos = new FileOutputStream(caminhoArquivo)) {

            StringBuilder hexString = new StringBuilder();

            // Converte o array de bytes do resumo em uma representação hexadecimal e anexa ao StringBuilder
            for (byte b : resumo) {
                hexString.append(String.format("%02x", 0xFF & b));
            }

            // Escreve a representação hexadecimal no arquivo
            fos.write(hexString.toString().getBytes());

        }  catch (IOException e) {
            System.err.println("Erro");
        }
    }
}


