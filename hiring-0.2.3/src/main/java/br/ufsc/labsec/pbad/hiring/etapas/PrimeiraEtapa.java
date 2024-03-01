package br.ufsc.labsec.pbad.hiring.etapas;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import br.ufsc.labsec.pbad.hiring.criptografia.resumo.Resumidor;
import br.ufsc.labsec.pbad.hiring.Constantes;

/**
 * <b>Primeira etapa - obter o resumo criptográfico de um documento</b>
 * <p>
 * Basta obter o resumo criptográfico do documento {@code textoPlano.txt}.
 * <p>
 * Os pontos a serem verificados para essa etapa ser considerada concluída
 * são os seguintes:
 * <ul>
 * <li>
 * obter o resumo criptográfico do documento, especificado na descrição
 * dessa etapa, usando o algoritmo de resumo criptográfico conhecido por
 * SHA-256;
 * </li>
 * <li>
 * armazenar em disco o arquivo contendo o resultado do resumo criptográfico,
 * em formato hexadecimal.
 * </li>
 * </ul>
 */
public class PrimeiraEtapa {

    public static void executarEtapa() {
        Resumidor resumidor;
        try {   
            resumidor = new Resumidor();
            File arquivoDeEntrada = new File(Constantes.caminhoTextoPlano);
            byte[] resumoCriptografico = resumidor.resumir(arquivoDeEntrada);
            resumidor.escreveResumoEmDisco(resumoCriptografico, Constantes.caminhoResumoCriptografico);
            System.out.println("Armazenado");
        } catch (NoSuchAlgorithmException | IOException x) {
            x.printStackTrace();
        }
    }
}
