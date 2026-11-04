# Modo de correção automática

O modo de correção existe para **subir a integridade real**, não a nota. Cada mudança precisa de
autorização, ser mínima e vir acompanhada de evidência (teste) de que funcionou sem regressão.

## Fluxo

1. **Linha de base**
   ```bash
   python3 <skill>/scripts/sentinel.py audit <projeto> --run-tests
   python3 <skill>/scripts/sentinel.py snapshot <projeto> antes
   ```
   Confirme que o repositório está limpo (`git status`) ou sugira um branch/commit antes — assim o
   usuário pode desfazer tudo com facilidade. Não faça commit sem pedido.

2. **Priorização** (maior risco primeiro, depois maior ganho por esforço)
   1. CRÍTICO confirmado (segredos expostos, injeção, erro de compilação)
   2. ALTO de segurança (authz, XSS, path traversal, deps com correção disponível)
   3. Testes falhando (causa raiz)
   4. Demais ALTO, depois MÉDIO de estabilidade/integridade
   5. BAIXO/INFO só se o usuário pedir

3. **Proposta** — para cada item ou lote coeso, apresente:
   ```
   Correção #N — [GRAVIDADE] Título (arquivo:linha)
   Problema: ...
   Mudança proposta: (diff resumido)
   Risco de regressão: baixo/médio/alto — por quê
   Teste que prova: nome do teste (novo ou existente) que falha antes e passa depois
   Requer autorização especial? (config / dependência / schema / CI)
   ```
   Aguarde "sim" explícito. Autorização para código **não** cobre: `package.json`/lockfile
   (`npm audit fix`, novas dependências), arquivos de configuração, migrações/banco, CI, remoção de
   arquivos. Peça separadamente.

4. **Implementação**
   - Mudança mínima, mesmo estilo do projeto, sem refatorar o que não foi pedido.
   - Preserve a API pública; se precisar mudar contrato, diga isso na proposta.
   - Escreva o teste primeiro quando possível (reproduz o bug → corrige → verde).
   - Nunca: desabilitar/pular testes, afrouxar asserções, adicionar `// sentinel-ignore` ou
     `eslint-disable` para esconder achado real, apagar código "suspeito" sem entender.
   - Segredos: remova do código, use variável de ambiente, e **avise que a credencial deve ser
     rotacionada** (continua no histórico git). Ofereça instruções de limpeza de histórico, sem executar.

5. **Reverificação**
   ```bash
   python3 <skill>/scripts/sentinel.py audit <projeto> --run-tests
   # refaça a triagem/revisão das áreas alteradas e atualize findings/manual.json
   python3 <skill>/scripts/sentinel.py rescore <projeto>
   python3 <skill>/scripts/sentinel.py compare <projeto> antes
   ```
   Se triagens manuais antigas apontavam para linhas que mudaram, revise-as — `file`/`line` desatualizados
   deixam de casar e o achado volta (comportamento intencional: na dúvida, o risco reaparece).

6. **Relato** — tabela antes × depois (de `comparison.md`), lista de correções aplicadas com
   arquivo:linha, achados resolvidos, **novos achados/regressões** (nunca omitir), pendências e o
   novo cadeado. Se a nota não subiu como esperado, explique qual teto continua ativo.

## Exemplo de relato

```
CODE SENTINEL — Modo de correção
CIS: 22 → 58 (+36) · Nível 1 Código Exposto → Nível 2 Proteção Fraca
Resolvidos (9): SQL injection em /users, command injection em /ping, eval em /calc, ...
Novos/regressões (0)
Pendências que mantêm o teto 59: chave AWS ainda no histórico git (rotação pendente pelo usuário);
minimist 1.2.0 → precisa de autorização para atualizar dependências.
```
