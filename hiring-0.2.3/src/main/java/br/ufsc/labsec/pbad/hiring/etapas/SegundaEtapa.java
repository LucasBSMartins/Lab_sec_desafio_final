package br.ufsc.labsec.pbad.hiring.etapas;

import br.ufsc.labsec.pbad.hiring.criptografia.chave.*;
import br.ufsc.labsec.pbad.hiring.Constantes;

import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

/**
 * <b>Segunda etapa - gerar chaves assimétricas</b>
 * <p>
 * A partir dessa etapa, tudo que será feito envolve criptografia assimétrica.
 * A tarefa aqui é parecida com a etapa anterior, pois refere-se apenas a
 * criar e armazenar chaves, mas nesse caso será usado um algoritmo de
 * criptografia assimétrica, o ECDSA.
 * <p>
 * Os pontos a serem verificados para essa etapa ser considerada concluída
 * são os seguintes:
 * <ul>
 * <li>
 * gerar um par de chaves usando o algoritmo ECDSA com o tamanho de 256 bits;
 * </li>
 * <li>
 * gerar outro par de chaves, mas com o tamanho de 521 bits. Note que esse
 * par de chaves será para a AC-Raiz;
 * </li>
 * <li>
 * armazenar em disco os pares de chaves em formato PEM.
 * </li>
 * </ul>
 */
public class SegundaEtapa {

    public static void executarEtapa() {
        GeradorDeChaves geradorDeChaves;

        try {
            // Cria um objeto GeradorDeChaves com o algoritmo especificado
            geradorDeChaves = new GeradorDeChaves(Constantes.algoritmoChave);

            // Gera um par de chaves para o User
            KeyPair conjuntoChaves256 = geradorDeChaves.gerarParDeChaves(256);
            System.out.println("Chave do usuário gerada com sucesso.");

            // Gera um par de chaves de 521 bits
            KeyPair conjuntoChaves521 = geradorDeChaves.gerarParDeChaves(521);
            System.out.println("Chave da AC-Raiz gerada com sucesso.");

            // Escreve a chave privada e pública do User em arquivos
            EscritorDeChaves.escreveChaveEmDisco(conjuntoChaves256.getPrivate(), Constantes.caminhoChavePrivadaUsuario, "EC PRIVATE KEY");
            EscritorDeChaves.escreveChaveEmDisco(conjuntoChaves256.getPublic(), Constantes.caminhoChavePublicaUsuario, "EC PUBLIC KEY");
            System.out.println("Chaves do usuário salvas com sucesso.");

            // Escreve a chave privada e pública da AC em arquivos
            EscritorDeChaves.escreveChaveEmDisco(conjuntoChaves521.getPrivate(), Constantes.caminhoChavePrivadaAc, "EC PRIVATE KEY");
            EscritorDeChaves.escreveChaveEmDisco(conjuntoChaves521.getPublic(), Constantes.caminhoChavePublicaAc, "EC PUBLIC KEY");
            System.out.println("Chaves da AC-Raiz salvas com sucesso.");

        } catch (NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }
    }

}
