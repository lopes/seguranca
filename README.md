# O Tao do Desenvolvimento Seguro
Este guia apresenta práticas de desenvolvimento seguro.  Cada tópico possui boas práticas de segurança pertinentes àquele assunto.  Além disso, para cada tópico há uma classe implementada no arquivo `seguranca.py`, com exemplos práticos.  O mais interessante a se notar é que, normalmente, é muito fácil implementar as boas práticas de segurança no código, o que deve servir como motivador para sua adoção.

### Dependências
Pacotes no Ubuntu --os dois últimos são requisitos do pyopenssl: `python3`, `python-dev` e `libpq-dev`.

Além deles, o arquivo `requirements.txt` tem a lista completa de dependências para execução do `seguranca.py`.


## Lista de Abreviaturas
```
AD          Active Directory
AES         Advanced Encryption Standard
API         Application Programming Interface
CBC         Cipher Block Chaining
CRL         Certificate Revocation List --o mesmo que LCR
ECB         Electronic Codebook
ECC         Eliptic Curve Cryptography
FTP         File Transfer Protocol
GMT         Greenwich Mean Time
HTTP        Hypertext Transfer Protocol
HTTPS       Hypertext Transfer Protocol Secure
LCR         Lista de Certificados Revogados
LDAP        Lightweight Directory Access Protocol
LDAPS       Lightweight Directory Access Protocol Secure
MD          Message Digest
ORM         Object-relational Mapping
RFC         Request for Comments
RSA         Rivest, Shamir, Adleman
SHA         Secure Hash
SIEM        Security Information and Event Management
SMB         Server Message Block
SNMP        Simple Network Management Protocol
SQL         Structured Query Language
SSH         Secure Shell
SSL         Secure Sockets Layer
TLS         Transport Layer Security
```


## 0. Criptografia
0. **NUNCA** crie seu sistema criptográfico: use aqueles já existentes.
1. Entenda o que são as criptografias simétrica e assimétrica.
2. Na criptografia simétrica, prefira usar o AES.
3. Na criptografia assimétrica, prefira usar o RSA ou o ECC.
4. Entenda o que são hashes e hashes criptografados.
5. Evite usar o MD5 ou o SHA-1 --prefira o SHA-256, por exemplo.
6. Nas cifras de bloco, evite usar o modo ECB --prefira o CBC.
7. Entenda que criptografia é diferente de codificação.
8. Use implementações amplamente testadas dos algoritmos criptográficos em vez de fazê-las por conta própria.

### 0.1. Exemplos
A classe `Criptografia` implementa exemplos pertinentes a este tópico.  Veja como usá-la:

```python
>>> from seguranca import Criptografia
>>> c = Criptografia()
>>> c.criptografa('foo', 'bar')
b'oV+L64jRpAi8bj3jI/sMTTUDmpcQrCQLJg6M51nEOKw='
>>> c.decriptografa('oV+L64jRpAi8bj3jI/sMTTUDmpcQrCQLJg6M51nEOKw=', 'bar')
'foo'
```


## 1. Senhas
1. Não limite o conjunto de caracteres das senhas.
2. Permita senhas realmente longas --e.g., 160 caracteres.
3. Proteja as senhas antes de armazená-las --e.g., usando *salt*.
4. Considere usar hashes criptográfados na proteção da senha.
5. Trate os *salts* e as credenciais de hash como chaves privadas.
6. Crie parâmetros mínimos de senha --e.g., 12 caracteres, com letras minúsculas, maiúsculas, números e não-alfanuméricos.

### 1.1. Exemplos
Exemplos deste tópico são implementados na classe `Senhas`.  Pode ser usada da seguinte forma:

```python
>>> from seguranca import Senhas
>>> s = Senhas()
>>> s.protege_senha_hmac_sha256('minha senha fort3!', '0$1I43f8', '81&69Ta0')
'0$1I43f8ee6bf9ca692a62390122001aea0613ae54107b645ecaef5405d7a840d1fb4445'
```


## 2. Autenticação
1. Sempre faça autenticação negativa: variáveis que permitirão a entrada devem ser inicializadas como *False*.
2. Prefira usar sistemas de autenticação existentes em vez de criar um novo --e.g., LDAP, AD e OAuth.
3. Mensagens de erro de autenticação devem informar o problema sem expor dados sensíveis, como nomes de usuário e versões de software.
4. Sempre que possível, implemente o duplo fator de autenticação --RFCs 4226 ou 6238.
5. Atenção ao usar certificados digitais para autenticação: um sistema que use essa técnica deve abrir o certificado, baixar a CRL relacionada, verificar se o certificado em questão está lá, verificar  a cadeia de emissão do certificado, obter o identificador do usuário gravado no certificado, verificar se aquele identificador está permitido a acessar o sistema e, só então, permitir o acesso.


## 3. Validação
1. Valide todos os dados de entrada adequadamente.
2. Trate com atenção caracteres especiais, como aspas simples e duplas.
3. Preste atenção aos *ranges* nos campos da sua aplicação --e.g., um campo para CPF não deveria permitir o envio de 1024 caracteres.
4. Em aplicações web, validações no lado cliente devem ser refeitas no servidor.
5. Parametrize consultas SQL, use um ORM ou estude a utilização de *stored procedures*.
6. Considere como dados de entrada cabeçalhos HTTP, parâmetros GET/POST, cookies e arquivos, por exemplo.
7. Atenção aos cookies: evite armazenar dados sensíveis neles e defina uma data de expiração da sessão.


## 4. Transferências
1. Em aplicações web, use HTTPS em vez do HTTP.
2. Prefira transferir arquivos via SSH; evite FTP ou SMB.
3. No servidor, desabilite versões inseguras de protocolos de criptografia --e.g., SSLv2 e SSLv3.
4. Crie senhas fortes para cada serviço e evite compartilhá-las entre eles.
5. Considere criptografar todas as conexões que forem feitas pela aplicação --e.g., LDAP over TLS/SSL (LDAPS) e SNMPv3.


## 5. Logs
1. Defina informações importantes que precisam ser armazenadas para fins de auditoria.
2. Considere usar bibliotecas específicas para a geração de logs.
3. Estruture os logs de acordo com algum padrão; evite criar novos --e.g., syslog-ng e ISO 8601 para datas.
4. Projete seu sistema de logs considerando que ele eventualmente será exportado para um SIEM.
5. **NUNCA** exponha informações sensíveis em logs --e.g., senhas.
6. Lembre-se que haverá geração de logs em várias camadas; não reinvente a roda --e.g., uma aplicação web poderia guardar somente o que e quando o usuário fez determinada coisa no programa, pois endereços IP e falhas de login estariam nos logs do servidor web ou do sistema operacional.
7. Mantenha o tempo dos servidores atualizados de acordo com um serviço confiável e único dentro do domínio, para manter o padrão --e.g., ntp.br.
8. Prefira armazenar datas de logs com o fuso GMT+0, ajustando o fuso apenas na apresentação para o auditor.
9. Para facilitar futuras pesquisas, defina níveis de log padrões para sua aplicação --e.g., *debug*, *info*, *warning*, *error e *critical*.


## 6. Certificados Digitais
1. Ao usar certificados em software, tenha atenção a quem tem acesso ao servidor onde ele está instalado.
2. De forma segura, remova do servidor certificados vencidos, revogados ou inutilizados por quaisquer outros motivos.
3. Mantenha algum tipo de controle de validade de certificados digitais, considerando que leva-se um tempo entre o pedido de renovação e a emissão do novo certificado --dependendo da morosidade do processo de aquisição do certificado, da criticidade e período de validade dele, considere renovar com 6 meses de antecedência.
4. Evite usar um certificado para mais de uma finalidade.
5. Certificados *wildcard* devem receber atenção especial: o ideal é que seu 'instalador' seja restrito a poucas pessoas e servidores; o uso ideal dele seria em um proxy reverso, fechando conexões seguras com clientes e esse proxy fechando conexões seguras com os servidores usando outros certificados.


## 7. Segregação de Funções
1. Crie contas administrativas separadas das de usuários comuns.
2. Restrinja o acesso de contas administrativas em redes ou endereços IP específicos.
3. Aumente o nível de segurança para contas administrativas --e.g., senhas realmente longas (> 40 caracteres), duplo fator de autenticação e, possivelmente, com certificado digital (token ou smart card).
4. Mantenha o princípio do menor privilégio, i.e., o usuário deve possuir permissões mínimas para realizar seu trabalho e a aplicação deve garantir que isso possa ser configurado.
5. Crie usuários específicos para executar tarefas da aplicação --e.g., banco de dados e sistema operacional.


## 8. Nuvem
0. Entenda que *nuvem*, no fundo, significa um servidor alocado em algum local remoto.
1. Ao usar serviços 'na nuvem', procure saber mais sobre o seu provedor: casos de sucesso, clientes, garantias de segurança, backup, recuperação de desastres etc.
2. Descubra onde, de fato, os dados serão armazenados ou processados; não se esqueça que cada país possui a sua legislação e ela pode afetar o seu serviço.
3. Leia e entenda os termos de serviço do provedor; atenção especial à cláusulas de confidencialidade das informações que serão armazenadas/processadas e ao que acontecerá com elas em caso de cancelamento do serviço --lembre-se que muitas empresas poderão nunca deletar realmente tais informações e outras poderão usá-las ou vendê-las em parte ou na totalidade.
4. Preveja um cenário de migração do serviço para outro provedor ou até para servidores internos; procure saber como o provedor a ser contratado trata essa possibilidade.
5. Avalie os riscos de expor as informações na nuvem; essa avaliação deve levar em consideração a classificação das informações que serão enviadas para o provedor contratado.
6. Considere fortemente as práticas do item 4, Transferências, ao trafegar dados locais para a nuvem e vice-versa.


## 9. Testes e Análises de Vulnerabilidade
1. Realize análises de vulnerabilidade periodicamente nas aplicações.
2. Adicione uma etapa de análise de vulnerabilidades ao processo de desenvolvimento de software.
3. Publique aplicações apenas após tratar todas as vulnerabilidades listadas nas análises.
4. Lembre-se que é mais fácil tratar vulnerabilidades em ambientes de homologação do que de produção.
5. Separe fisica e logicamente os ambientes de homologação e produção.
6. Crie ambientes de homologação o mais parecidos possível dos seus pares de produção.


## 10. Outros
1. Garanta que o sistema esteja alinhado com a legislação vigente do local onde for usado --e.g., [Marco Civil da Internet](https://www.planalto.gov.br/ccivil_03/_ato2011-2014/2014/lei/l12965.htm).
2. Crie um processo formal para implantação de sistemas, que deverá garantir, entre outras coisas, que apenas os arquivos essenciais sejam colocados em produção --e.g., estruturas de controle de versão (e.g., diretórios .git) deveriam ser apagados.
3. Mantenha uma rotina de atualização do software e suas dependências, como APIs e sistemas operacionais.
4. Mantenha atualizada a documentação, seja ela qual for, da aplicação, pois em caso de problemas, ela será uma das primeiras fontes de consulta.
5. Documente todas as mudanças no software, preferencialmente usando um sistema de controle de versões de código.
6. Mudanças na infraestrutura deveriam ser documentadas, para facilitar o rastreio de problemas --e.g., atualização do servidor e entrada em produção de uma nova versão de determinado serviço.



## Referências
1. Open Web Application Security Project (OWASP).  Password Storage Cheat Sheet.  Disponível em: [https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet](https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet).
2. National Institute of Standards and Technology (NIST).  Recommendation for Block Cipher Modes of Operation.  NIST Special Publication 800-38A.  2001.  Disponível em: [http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf](http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf).
3. Open Web Application Security Project (OWASP).  OWASP Proactive Controls.  Disponível em: [https://www.owasp.org/index.php/OWASP_Proactive_Controls](https://www.owasp.org/index.php/OWASP_Proactive_Controls).
4. Open Web Application Security Project (OWASP).  SQL Injection Prevention Cheat Sheet.  Disponível em: [https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet](https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet).
5. Open Web Application Security Project (OWASP).  Session Management Cheat Sheet.  Disponível em: [https://www.owasp.org/index.php/Session_Management_Cheat_Sheet](https://www.owasp.org/index.php/Session_Management_Cheat_Sheet).
6. Open Web Application Project (OWASP).  Secure Coding Principles.  Disponível em: [https://www.owasp.org/index.php/Secure_Coding_Principles](https://www.owasp.org/index.php/Secure_Coding_Principles).
7. International Information System Security Certification Consortium (ISC)².  The Ten Best Practices for Secure Software Development.


## Sobre
Criado por José Lopes de Oliveira Jr. e licenciado sob a GNU General Public License v3 ou posterior --leia o arquivo `LICENSE` para mais informações.

### Agradecimentos
* [Cemig](http://www.cemig.com.br)
* [Comunidade Python Brasil](http://python.org.br)
