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
        GeradorDeChaves geradorDeChaves256;
        GeradorDeChaves geradorDeChaves521;

        try {
            geradorDeChaves256 = new GeradorDeChaves(Constantes.algoritmoChave);
            KeyPair conjuntoChaves256 = geradorDeChaves256.gerarParDeChaves(256);

            geradorDeChaves521 = new GeradorDeChaves(Constantes.algoritmoChave);
            KeyPair conjuntoChaves521 = geradorDeChaves521.gerarParDeChaves(521);

            EscritorDeChaves.escreveChaveEmDisco(conjuntoChaves256.getPrivate(), Constantes.caminhoChavePrivadaUsuario, "EC PRIVATE KEY");
            EscritorDeChaves.escreveChaveEmDisco(conjuntoChaves256.getPublic(), Constantes.caminhoChavePublicaUsuario, "EC PUBLIC KEY");
            EscritorDeChaves.escreveChaveEmDisco(conjuntoChaves521.getPrivate(), Constantes.caminhoChavePrivadaAc, "EC PRIVATE KEY");
            EscritorDeChaves.escreveChaveEmDisco(conjuntoChaves521.getPublic(), Constantes.caminhoChavePublicaAc, "EC PUBLIC KEY");

        } catch (NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }
    }

}
