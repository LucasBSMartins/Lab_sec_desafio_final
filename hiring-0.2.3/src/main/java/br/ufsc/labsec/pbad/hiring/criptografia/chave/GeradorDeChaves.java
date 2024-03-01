package br.ufsc.labsec.pbad.hiring.criptografia.chave;

import java.security.*;

/**
 * Classe responsável por gerar pares de chaves assimétricas.
 *
 * @see KeyPair
 * @see PublicKey
 * @see PrivateKey
 */
public class GeradorDeChaves {

    private String algoritmo;
    private KeyPairGenerator generator;

    /**
     * Construtor.
     *
     * @param algoritmo algoritmo de criptografia assimétrica a ser usado.
     */
    public GeradorDeChaves(String algoritmo) {
        // TODO implementar
    }

    /**
     * Gera um par de chaves, usando o algoritmo definido pela classe, com o
     * tamanho da chave especificado.
     *
     * @param tamanhoDaChave tamanho em bits das chaves geradas.
     * @return Par de chaves.
     * @see SecureRandom
     */
    public KeyPair gerarParDeChaves(int tamanhoDaChave) {
        // TODO implementar
        return null;
    }

}
