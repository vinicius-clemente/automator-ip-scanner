# Automator IP Scanner (L3 Network Auditor)

Ferramenta de automação desenvolvida em Python para varredura e auditoria de blocos e ranges de endereços IP e rotas em equipamentos de Camada 3 (L3), identificando rapidamente se um prefixo está livre ou alocado e mapeando em qual equipamento e interface ele está ativo.

## Funcionalidades

- **Auditoria de Ranges e Rotas L3:** Conecta-se via SSH aos roteadores e switches L3 do inventário para verificar a ocupação de blocos, rotas e endereços IP.
- **Identificação de Alocação:** Localiza exatamente em qual equipamento e interface/sub-interface um range ou IP específico está configurado ou roteado.
- **Prevenção de Conflitos (IPAM Check):** Valida se um bloco está livre antes de realizar novas alocações ou migrações de rede.
- **Execução em Lote:** Varre múltiplos dispositivos de forma automatizada com tratamento de exceções SSH e timeouts.

## Tecnologias Utilizadas

- **Python 3.x**
- **Netmiko / Paramiko:** Gerenciamento automatizado de sessões SSH e coleta de tabelas de roteamento e interfaces nos ativos L3.

## Como Utilizar

1. Clone o repositório:

       git clone https://github.com/vinicius-master/automator-ip-scanner.git
       cd automator-ip-scanner

2. Instale as dependências:

       pip install -r requirements.txt

3. Preencha o arquivo de inventário (`devices.txt`) com os endereços IP dos equipamentos L3 a serem auditados.

4. Execute o script:

       python ip-scanner.py

   *(Ajuste o nome do arquivo `.py` conforme o script principal na pasta).*

## Licença

Este projeto está sob a licença MIT. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.
