# O Tao do Desenvolvimento Seguro
Este guia apresenta práticas de desenvolvimento seguro.  Cada tópico possui boas práticas de segurança pertinentes àquele assunto.  Além disso, para cada tópico há uma classe implementada no arquivo `seguranca.py`, com exemplos práticos.  O mais interessante a se notar é que, normalmente, é muito fácil implementar as boas práticas de segurança no código, o que deve servir como motivador para sua adoção.

### Dependências
Pacotes no [Ubuntu](http://www.ubuntu.com/) --os dois últimos são requisitos do pyopenssl: `python3`, `python-dev` e `libpq-dev`.

Além deles, o arquivo `requirements.txt` tem a lista completa de dependências para execução do `seguranca.py`.


## Lista de Abreviaturas
```
AD          Active Directory
AES         Advanced Encryption Standard
API         Application Programming Interface
CBC         Cipher Block Chaining
CRL         Certificate Revocation List --o mesmo que LCR
CTR         Counter --modo de criptografia de bloco
ECB         Electronic Codebook
ECC         Eliptic Curve Cryptography
ECDSA       Elliptic Curve Digital Signature Algorithm
FTP         File Transfer Protocol
GMT         Greenwich Mean Time
HTTP        Hypertext Transfer Protocol
HTTPS       Hypertext Transfer Protocol Secure
LCR         Lista de Certificados Revogados
LDAP        Lightweight Directory Access Protocol
LDAPS       Lightweight Directory Access Protocol Secure
MD          Message Digest
ORM         Object-relational Mapping
PBKDF2      Password-Based Key Derivation Function 2
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
1. Entenda o que são as criptografias [simétrica](https://en.wikipedia.org/wiki/Symmetric-key_algorithm) e [assimétrica](https://en.wikipedia.org/wiki/Public-key_cryptography).
2. Na criptografia simétrica, prefira usar o [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard).
3. Na criptografia assimétrica, prefira usar o [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) ou algum baseado em [ECC](https://en.wikipedia.org/wiki/Elliptic_curve_cryptography), como [ECDSA](https://wiki.openssl.org/index.php/Elliptic_Curve_Cryptography) ou [Ed25519](https://ed25519.cr.yp.to/).
4. Entenda o que são [*hashes*](https://en.wikipedia.org/wiki/Hash_function) e [*hashes* autenticados](https://en.wikipedia.org/wiki/Hash-based_message_authentication_code).
5. Prefira usar o algoritmo de *hash* [SHA-2](https://en.wikipedia.org/wiki/SHA-2) --*digest* &gt;= 256 bits-- em vez do [MD5](https://en.wikipedia.org/wiki/MD5#Overview_of_security_issues) ou [SHA-1](https://en.wikipedia.org/wiki/SHA-1#Attacks).
6. Nas cifras de bloco, prefira os modos [CBC](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29) ou [CTR](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_.28CTR.29) em vez do [ECB](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_.28ECB.29).
7. Entenda que criptografia é diferente de codificação.
8. Use implementações de código-aberto<sup>1</sup> amplamente testadas dos algoritmos criptográficos em vez de fazê-las por conta própria.
9. Utilize bibliotecas que requeiram o mínimo de intervenção do programador, como a [NaCl](https://nacl.cr.yp.to/).


### 0.1. Exemplos
A classe `Criptografia` implementa exemplos pertinentes a este tópico.  Veja como usá-la:

```python
>>> from seguranca import Criptografia
>>> c = Criptografia()
>>> c.pycrypto_enc('foo', 'bar')
'7AvPa1diRCDYrkp5OHB4LhoIMTRKcIcSR/By7c7NqGA='
>>> c.pycrypto_dec('7AvPa1diRCDYrkp5OHB4LhoIMTRKcIcSR/By7c7NqGA=', 'bar')
'foo'
>>> c.pynacl_enc('foo', 'bar')
'707b411092496079d4f5e5db22fd13ca50836606e1cf9cfae5ce6c1945ae03b1b15c51fd9c9b98b19e787e'
>>> c.pynacl_dec('707b411092496079d4f5e5db22fd13ca50836606e1cf9cfae5ce6c1945ae03b1b15c51fd9c9b98b19e787e', 'bar')
'foo'
```


## 1. Senhas
1. Não limite o conjunto de caracteres das senhas.
2. Permita senhas realmente longas --e.g., 160 caracteres.
3. Proteja as senhas antes de armazená-las --e.g., usando [*salt*](https://en.wikipedia.org/wiki/Salt_(cryptography)).
4. Considere usar *hashes* criptográfados na proteção da senha.
5. Trate os *salts* e as credenciais de *hashes* autenticados como chaves privadas.
6. Crie parâmetros mínimos de senha --e.g., 12 caracteres, com letras minúsculas `[a-z]`, maiúsculas `[A-Z]`, números `[0-9]` e não-alfanuméricos `[!@#$%~^...]`.
7. Use algoritmos de *hash* cujo tempo de processamento possa ser configurado, pois eles tendem a ser mais seguros para essa finalidade --e.g., [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) e [Argon2](https://en.wikipedia.org/wiki/Argon2).

### 1.1. Exemplos
Exemplos deste tópico são implementados na classe `Senhas`.  Pode ser usada da seguinte forma:

```python
>>> from seguranca import Senhas
>>> s = Senhas()
>>> s.protege_senha_hmac_sha256('minha senha fort3!', '0$1I43f8', '81&69Ta0')
'0$1I43f8ee6bf9ca692a62390122001aea0613ae54107b645ecaef5405d7a840d1fb4445'
>>> s.protege_senha_pbkdf2('minha senha fort3!', '0$1I43f8', 100000)
'adbb4881cac9bcb44d7e8adb0d07178fd3b71895c6c9465330f8fc2122099f35'
```


## 2. Autenticação
1. Sempre faça autenticação negativa: variáveis que permitirão a entrada devem ser inicializadas como *False*.
2. Prefira usar sistemas de autenticação existentes em vez de criar um novo --e.g., LDAP, AD e OAuth.
3. Mensagens de erro de autenticação devem informar o problema sem expor dados sensíveis, como nomes de usuário e versões de software.
4. Sempre que possível, implemente o duplo fator de autenticação --RFCs [4226](https://www.ietf.org/rfc/rfc4226.txt) ou [6238](https://www.ietf.org/rfc/rfc6238.txt).
5. Atenção ao usar certificados digitais para autenticação: um sistema que use essa técnica deve abrir o certificado, baixar a CRL relacionada, verificar se o certificado em questão está lá, verificar  a cadeia de emissão do certificado, obter o identificador do usuário gravado no certificado, verificar se aquele identificador está permitido a acessar o sistema e, só então, permitir o acesso.

### 2.1. Exemplos
Exemplos implementados na classe `Autenticacao`.  Uso:

```python
>>> from seguranca import Autenticacao
>>> a = Autenticacao()
>>> a.segundo_fator('time', 'O}PIk7*9')
613083
>>> a.segundo_fator('hmac', 'O}PIk7*9')
236466
```


## 3. Validação
1. Valide todos os dados de entrada adequadamente.
2. Trate com atenção caracteres especiais, como aspas simples e duplas.
3. Preste atenção aos *ranges* nos campos da sua aplicação --e.g., um campo para CPF não deveria permitir o envio de 1024 caracteres.
4. Em aplicações web, validações no lado cliente devem ser refeitas no servidor.
5. Parametrize consultas SQL, use um [ORM](https://en.wikipedia.org/wiki/Object-relational_mapping) ou estude a utilização de [*stored procedures*](https://en.wikipedia.org/wiki/Stored_procedure).
6. Considere como dados de entrada: cabeçalhos HTTP, parâmetros GET/POST, *cookies* e arquivos, por exemplo.
7. Atenção aos *cookies*: evite armazenar dados sensíveis neles e defina uma data de expiração da sessão.

### 3.1. Exemplos
A classe `Validacao` implementa exemplos desse tópico.  Uso:

```python
>>> from seguranca import Validacao
>>> v = Validacao()
>>> v.codificahex('Companhia Energética de Minas Gerais')
'436f6d70616e68696120456e657267c3a974696361206465204d696e617320476572616973'
>>> v.decodificahex('436f6d70616e68696120456e657267c3a974696361206465204d696e617320476572616973')
'Companhia Energética de Minas Gerais'
```


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

### 5.1. Exemplos
Exemplos de uso --classe `Logs`:

```python
>>> from seguranca import Logs
>>> u = input('Nome de usuário: ')
Nome de usuário: cemig
>>> l = Logs()
>>> l.log_aviso('usuário inválido: {}'.format(u))
2016-08-09 11:03:00,586 WARNING: usuário inválido: cemig
>>> print(l.tamanho_log(1000, 60))
...
```


## 6. Certificados Digitais
1. Ao usar certificados em software, tenha atenção a quem tem acesso ao servidor onde ele está instalado.
2. De forma segura, remova do servidor certificados vencidos, revogados ou inutilizados por quaisquer outros motivos.
3. Mantenha algum tipo de controle de validade de certificados digitais, considerando que leva-se um tempo entre o pedido de renovação e a emissão do novo certificado --dependendo da morosidade do processo de aquisição do certificado, da criticidade e período de validade dele, considere renovar com 6 meses de antecedência.
4. Evite usar um certificado para mais de uma finalidade.
5. Certificados *wildcard* devem receber atenção especial: o ideal é que seu 'instalador' seja restrito a poucas pessoas e servidores; o uso ideal dele seria em um proxy reverso, fechando conexões seguras com clientes e esse proxy fechando conexões seguras com os servidores usando outros certificados.
6. Revogue o certificado a qualquer evidência de comprometimento do mesmo --lembre-se que, em posse dele, qualquer pessoa pode decriptografar informações, forjar serviços 'seguros' ou assinar documentos como o dono do certificado.

### 6.1. Exemplos
A classe `CertificadosDigitais` tem alguns exemplos de uso e pode ser usada como neste exemplo:

```python
>>> from seguranca import CertificadosDigitais
>>> c = CertificadosDigitais()
>>> print(c.le_cert_p12('/home/forkd/Downloads/certest.p12'))
...
```


## 7. Segregação de Funções
1. Crie contas administrativas separadas das de usuários comuns.
2. Restrinja o acesso de contas administrativas em redes ou endereços IP específicos.
3. Aumente o nível de segurança para contas administrativas --e.g., senhas realmente longas (&gt; 40 caracteres), duplo fator de autenticação e, possivelmente, com certificado digital (token ou *smart card*).
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

### 8.1. Exemplos
Exemplos na classe `Nuvem`.  Uso:

```python
>>> from seguranca import Nuvem
>>> n = Nuvem()
>>> n.upload_para_gdrive('/home/forkd/Downloads/certest.p12')
...
```


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



## Notas
1. Dos [princípios de Kerckhoff](https://en.wikipedia.org/wiki/Kerckhoffs%27s_principle) (1835-1903): os algoritmos devem ser abertos e as chaves, secretas --por extensão pode-se inferir que as implentações dos algoritmos deveriam ser igualmente abertas e o programador deveria ter conhecimento completo do código utilizado.


## Referências
1. Open Web Application Security Project (OWASP).  Password Storage Cheat Sheet.  Disponível em: [https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet](https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet).
2. National Institute of Standards and Technology (NIST).  Recommendation for Block Cipher Modes of Operation.  NIST Special Publication 800-38A.  2001.  Disponível em: [http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf](http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf).
3. Open Web Application Security Project (OWASP).  OWASP Proactive Controls.  Disponível em: [https://www.owasp.org/index.php/OWASP_Proactive_Controls](https://www.owasp.org/index.php/OWASP_Proactive_Controls).
4. Open Web Application Security Project (OWASP).  SQL Injection Prevention Cheat Sheet.  Disponível em: [https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet](https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet).
5. Open Web Application Security Project (OWASP).  Session Management Cheat Sheet.  Disponível em: [https://www.owasp.org/index.php/Session_Management_Cheat_Sheet](https://www.owasp.org/index.php/Session_Management_Cheat_Sheet).
6. Open Web Application Project (OWASP).  Secure Coding Principles.  Disponível em: [https://www.owasp.org/index.php/Secure_Coding_Principles](https://www.owasp.org/index.php/Secure_Coding_Principles).
7. International Information System Security Certification Consortium (ISC)².  The Ten Best Practices for Secure Software Development.
8. Hynek Schlawack.  Storing Passwords in a Highly Parallelized World.   [https://hynek.me/articles/storing-passwords](https://hynek.me/articles/storing-passwords)


## Sobre
Criado por José Lopes de Oliveira Jr. e licenciado sob a GNU General Public License v3 ou posterior --leia o arquivo `LICENSE` para mais informações.

### Agradecimentos
* [Cemig](http://www.cemig.com.br)
* [Comunidade Python Brasil](http://python.org.br)
