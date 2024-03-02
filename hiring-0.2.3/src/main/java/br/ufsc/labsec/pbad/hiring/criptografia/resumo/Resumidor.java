package br.ufsc.labsec.pbad.hiring.criptografia.resumo;
import br.ufsc.labsec.pbad.hiring.Constantes;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
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
        // Pega o tipo de algoritmo usado "SHA-256" por exemplo.
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
        
        FileInputStream fis = new FileInputStream(arquivoDeEntrada);
        byte[] bytes = new byte[(int) arquivoDeEntrada.length()];
        
        fis.read(bytes);
        fis.close();       
        
        byte[] resumo = this.md.digest(bytes);
        return resumo;
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
            for (byte b : resumo) {
                hexString.append(String.format("%02X", 0xFF & b));
            }
            fos.write(hexString.toString().getBytes());
        
        }  catch (IOException e) {
            System.err.println("Erro");
        }
    }
}


