package br.ufsc.labsec.pbad.hiring;
import br.ufsc.labsec.pbad.hiring.etapas.*;

/**
 * Classe principal, responsável por executar todas as etapas.
 */

public class ExecutarEtapas {

    public static void main(String[] args) {

        System.out.println("Primeira Etapa:");
        PrimeiraEtapa.executarEtapa();
        System.out.println();
        System.out.println("Segunda Etapa:");
        SegundaEtapa.executarEtapa();
        System.out.println();
        System.out.println("Terceira Etapa:");
        TerceiraEtapa.executarEtapa();
        System.out.println();
        System.out.println("Quarta Etapa:");
        QuartaEtapa.executarEtapa();
        System.out.println();
        System.out.println("Quinta Etapa:");
        QuintaEtapa.executarEtapa();
        System.out.println();
        System.out.println("Sexta Etapa:");
        SextaEtapa.executarEtapa();

    }
}
