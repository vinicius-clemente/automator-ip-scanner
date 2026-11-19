# automator-ip-scanner

AUTOMAÇÃO PARA REALIZAR UM SCAN NA ESTRUTURA L3 PARA VALIDAR E PROCURAR IPS E ROTAS



\# Automator IP Scanner (L3 Network Auditor)



Ferramenta de automacao desenvolvida em Python para varredura e auditoria de blocos e ranges de enderecos IP em equipamentos de Camada 3 (L3), identificando rapidamente se um prefixo esta livre ou alocado e mapeando em qual equipamento e interface ele esta ativo.



\## Funcionalidades



\- \*\*Auditoria de Ranges L3:\*\* Conecta-se via SSH aos roteadores e switches L3 do inventario para verificar a ocupacao de blocos e enderecos IP.

\- \*\*Identificacao de Alocacao:\*\* Localiza exatamente em qual equipamento e interface/sub-interface um range ou IP especifico esta configurado ou roteado.

\- \*\*Prevencao de Conflitos (IPAM Check):\*\* Valida se um bloco esta livre antes de realizar novas alocacoes ou migracoes de rede.

\- \*\*Execucao em Lote:\*\* Varre multiplos dispositivos de forma automatizada com tratamento de excecoes SSH e timeouts.



\## Tecnologias Utilizadas



\- \*\*Python 3.x\*\*

\- \*\*Netmiko / Paramiko:\*\* Gerenciamento de sessoes SSH e coleta de tabelas de roteamento/interfaces nos ativos L3.



\## Como Utilizar



1\. Clone o repositorio:

&#x20;  ```bash

&#x20;  git clone \[https://github.com/vinicius-master/automator-ip-scanner.git](https://github.com/vinicius-master/automator-ip-scanner.git)

&#x20;  cd automator-ip-scanner

