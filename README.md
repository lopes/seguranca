# O Tao do Desenvolvimento Seguro
Este guia apresenta práticas de desenvolvimento seguro.  Cada tópico possui boas práticas de segurança pertinentes àquele assunto.  Além disso, para cada tópico há --ou deveria haver :P-- uma classe implementada no arquivo `seguranca.py`, com exemplos práticos.  O mais interessante a se notar é que, normalmente, é muito fácil implementar as boas práticas de segurança no código, o que deve servir como motivador para sua adoção.

O guia é dividido em vários tópicos, cada um tratando de um assunto específico, que agrega as suas boas práticas.  Cada prática utiliza um verbo que indica a ação esperada do programador, como 'use', 'implemente' ou '[nunca] faça'.  Dado o grau de abstração deste guia, ele deve se encaixar em vários projetos e linguagens de programação, mas precisa ser adaptado a cada situação, i.e., poderá haver situações onde o programador precisará usar senhas curtas ou usar SMB para transferir arquivos.  Entretanto, casos específicos devem ser tratados como aquilo que são --exceções-- e, **principalmente**, [para quebrar regras, deve-se dominá-las primeiro](https://c1.staticflickr.com/9/8550/8711954278_667f63b745_z.jpg).  Em todo caso, a não-adoção de uma boa prática deve ser documentada e seguida de medidas de mitigação dos riscos associados.

### Dependências
Pacotes no [Ubuntu](http://www.ubuntu.com/) --os dois últimos são requisitos do pyopenssl: `python3`, `libffi-dev`, `python-dev` e `libpq-dev`.

Além deles, o arquivo `requirements.txt` tem a lista completa de dependências para execução do `seguranca.py`.


## Lista de Abreviaturas
```
AES         Advanced Encryption Standard
API         Application Programming Interface
CBC         Cipher Block Chaining
CRL         Certificate Revocation List --o mesmo que LCR
CTR         Counter --modo de criptografia de bloco
ECB         Electronic Codebook
ECC         Elliptic Curve Cryptography
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
3. Na criptografia assimétrica, prefira usar o [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) ou algum algoritmo baseado em [ECC](https://en.wikipedia.org/wiki/Elliptic_curve_cryptography), como [ECDSA](https://wiki.openssl.org/index.php/Elliptic_Curve_Cryptography) ou [Ed25519](https://ed25519.cr.yp.to/).
4. Entenda o que são [*hashes*](https://en.wikipedia.org/wiki/Hash_function) e [*hashes* autenticados](https://en.wikipedia.org/wiki/Hash-based_message_authentication_code).
5. Prefira usar o algoritmo de *hash* [SHA-2](https://en.wikipedia.org/wiki/SHA-2) --*digest* &gt;= 256 bits-- em vez do [MD5](https://en.wikipedia.org/wiki/MD5#Overview_of_security_issues) ou [SHA-1](https://en.wikipedia.org/wiki/SHA-1#Attacks).
6. Nas cifras de bloco, prefira os modos [CBC](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29) ou [CTR](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_.28CTR.29) em vez do [ECB](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_.28ECB.29).
7. Entenda que [criptografia é diferente de codificação](https://danielmiessler.com/study/encoding-encryption-hashing-obfuscation/).
8. Use implementações de código-aberto<sup>1</sup> e amplamente testadas dos algoritmos criptográficos, em vez de fazê-las por conta própria.
9. Utilize bibliotecas que requeiram o mínimo de intervenção do programador, como a [NaCl](https://nacl.cr.yp.to/), para evitar erros de programação.

### 0.1. Exemplos
A classe `Criptografia` implementa exemplos pertinentes a este tópico.  Veja como usá-la:

```python
>>> from seguranca import Criptografia
>>> c = Criptografia()
>>> c.pycrypto_enc('ataque ao amanhecer', ')s3nh4+mu1t0_S3kreT4&')
'zTztObz5VNexu8OWc+ZN6qlwPTgbC14MhC2cGpKmL2S5kI+VivbSpjDosXOSktIp'
>>> c.pycrypto_dec('zTztObz5VNexu8OWc+ZN6qlwPTgbC14MhC2cGpKmL2S5kI+VivbSpjDosXOSktIp', ')s3nh4+mu1t0_S3kreT4&')
'ataque ao amanhecer'
>>> c.pynacl_enc('ataque ao amanhecer', ')s3nh4+mu1t0_S3kreT4&')
'mjBjla9rVR4314t2YMRP+qYlY1VRn206EjzCdx+kPavgMklsveGoMFDdeq09B0MN4vcy0aH85Fiw0wY='
>>> c.pynacl_dec('mjBjla9rVR4314t2YMRP+qYlY1VRn206EjzCdx+kPavgMklsveGoMFDdeq09B0MN4vcy0aH85Fiw0wY=', ')s3nh4+mu1t0_S3kreT4&')
'ataque ao amanhecer'
```


## 1. Senhas
1. Não limite o conjunto de caracteres das senhas.
2. Permita senhas realmente longas --e.g., 160 caracteres.
3. Proteja as senhas antes de armazená-las --e.g., usando [*salt*](https://en.wikipedia.org/wiki/Salt_(cryptography)).
4. Considere usar *hashes* autenticados na proteção da senha.
5. Trate os *salts* e as credenciais de *hashes* autenticados como chaves privadas.
6. Crie parâmetros mínimos de senha --e.g., 12 caracteres, com letras minúsculas `[a-z]`, maiúsculas `[A-Z]`, números `[0-9]` e não-alfanuméricos `[!@#$%~^...]`.
7. Use algoritmos de *hash* cujo tempo de processamento possa ser configurado, pois eles tendem a ser mais seguros para essa finalidade --e.g., [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) e [Argon2](https://en.wikipedia.org/wiki/Argon2).

### 1.1. Exemplos
Exemplos deste tópico são implementados na classe `Senhas`, que pode ser usada da seguinte forma:

```python
>>> from seguranca import Senhas
>>> s = Senhas()
>>> s.protege_senha_hmac_sha256('senha super secreta', 'sal super secreto', 'chave do hmac [super secreta]')
'sal super secretoc4cd44c5487f0085e8a95e12ec627af7417ed43cf7e27d52f9a187cbfbbecc6d'
>>> s.protege_senha_pbkdf2('senha super secreta', 'sal super secreto', 100001)
'qjFxmVO0TJvCz5WLSFOI/cRAjvOYXp8r2+KA+yXUp1w='
>>> s.protege_senha_argon2('senha super secreta')
'$argon2i$v=19$m=512,t=2,p=2$RY6X+K5gL3W0c954OdJjpw$OwNj9fvVV31WBW6MxeA4UQ'
```


## 2. Autenticação e Autorização
1. Sempre faça autenticação negativa: variáveis que permitirão a entrada no sistema devem ser inicializadas para negar o acesso --cabe ao usuário provar que ele pode entrar.
2. Prefira usar sistemas de autenticação existentes em vez de criar um novo --e.g., [LDAP](https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol) e [OAuth](https://oauth.net/).
3. Mensagens de erro de autenticação devem informar o problema sem expor dados sensíveis, como nomes de usuário e versões de software.
4. Sempre que possível, implemente o duplo fator de autenticação --RFCs [4226](https://www.ietf.org/rfc/rfc4226.txt) ou [6238](https://www.ietf.org/rfc/rfc6238.txt).
5. Atenção ao usar certificados digitais para autenticação: um sistema que use essa técnica deveria abrir o certificado, baixar a CRL relacionada, verificar se o certificado em questão está lá, verificar  a cadeia de emissão do certificado, determinar se a cadeia é acreditada no sistema, obter o identificador do usuário gravado no certificado, verificar se aquele identificador está permitido a acessar o sistema e, só então, permitir o acesso.
6. Estude a utilização de um método bem definido de acesso às informações dentro do programa, como [RBAC](https://en.wikipedia.org/wiki/Role-based_access_control), [DAC](https://en.wikipedia.org/wiki/Discretionary_access_control), [MAC](https://en.wikipedia.org/wiki/Mandatory_access_control) ou [ACL](https://en.wikipedia.org/wiki/Access_control_list).

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
1. Valide todos os dados de entrada adequadamente, tratando com atenção caracteres especiais, como aspas simples e duplas.
2. Limite os *ranges* nos campos de entrada de dados do programa --e.g., um campo para CPF não deveria permitir o envio de 1024 caracteres.
3. Em aplicações web, validações no lado cliente devem ser refeitas no servidor.
4. Parametrize consultas SQL, use um [ORM](https://en.wikipedia.org/wiki/Object-relational_mapping) ou utilize de [*stored procedures*](https://en.wikipedia.org/wiki/Stored_procedure).
5. Considere como dados de entrada: cabeçalhos HTTP, parâmetros para métodos [GET/POST](http://www.w3schools.com/tags/ref_httpmethods.asp), [*cookies*](https://en.wikipedia.org/wiki/HTTP_cookie) e arquivos, por exemplo.
6. Atenção aos *cookies*: evite armazenar dados sensíveis neles, como senhas, e defina datas para expiração das sessões.

### 3.1. Exemplos
A classe `Validacao` implementa exemplos desse tópico.  Uso:

```python
>>> from seguranca import Validacao
>>> v = Validacao()
>>> v.codifica_b64('entrada duvidosa do usuário')
'ZW50cmFkYSBkdXZpZG9zYSBkbyB1c3XDoXJpbw=='
>>> v.decodifica_b64('ZW50cmFkYSBkdXZpZG9zYSBkbyB1c3XDoXJpbw==')
'entrada duvidosa do usuário'
```


## 4. Transferências
1. Em aplicações web, use [HTTPS](https://en.wikipedia.org/wiki/HTTPS) em vez do [HTTP](https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol).
2. Prefira transferir arquivos via [SSH](https://en.wikipedia.org/wiki/Secure_Shell); evite [FTP](https://en.wikipedia.org/wiki/File_Transfer_Protocol) ou [SMB](https://en.wikipedia.org/wiki/Server_Message_Block).
3. No servidor, [desabilite](http://disablessl3.com/) versões inseguras de protocolos de criptografia --e.g., SSLv2 e SSLv3.
4. Crie senhas fortes para cada serviço e evite compartilhá-las entre eles.
5. Considere criptografar todas as conexões que forem feitas pela aplicação --e.g., HTTPS, LDAP over TLS/SSL (LDAPS) e SNMPv3.


## 5. Logs
1. Defina informações importantes que precisam ser armazenadas para fins de auditoria.
2. Considere usar bibliotecas específicas para a geração de logs.
3. Estruture os logs de acordo com algum padrão; evite criar novos --e.g., [syslog-ng](https://en.wikipedia.org/wiki/Syslog-ng) e [ISO 8601](https://en.wikipedia.org/wiki/ISO_8601) para datas.
4. Projete seu sistema de logs considerando que ele eventualmente será exportado para um [SIEM](https://en.wikipedia.org/wiki/Security_information_and_event_management).
5. **NUNCA** exponha informações sensíveis em logs --e.g., senhas.
6. Defina os logs de forma que sejam facilmente integráveis com outros sistemas --e.g., gravar o endereço IP/MAC usado pelo usuário para entrar no programa, as ações realizadas pela conta durante a sessão e quando foi feito o *logout*; mais informações poderiam ser obtidas com o cruzamento de dados com outros sistemas de log.
7. Mantenha o tempo dos servidores atualizados de acordo com um serviço confiável e único dentro do domínio, para manter o padrão nos logs --e.g., [NTP.br](http://ntp.br).
8. Prefira armazenar datas de logs com o fuso GMT+0, ajustando o fuso apenas na apresentação para o auditor.
9. Para facilitar futuras pesquisas, defina níveis de log padrões para a aplicação --e.g., *debug*, *info*, *warning*, *error* e *critical*.

### 5.1. Exemplos
Exemplos de uso --classe `Logs`:

```python
>>> from seguranca import Logs
>>> l = Logs()
>>> u = input('Nome de usuário: ')
Nome de usuário: cemig
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
7. Defina políticas para gestão de cada tipo de certificados, como requisição, instalação, uso, renovação, revogação e descarte.

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
3. Aumente o nível de segurança para contas administrativas --e.g., senhas realmente longas (&gt; 40 caracteres), duplo fator de autenticação e, possivelmente, com certificado digital (*token* ou *smart card*).
4. Mantenha o princípio do menor privilégio, i.e., o usuário deve possuir permissões mínimas para realizar seu trabalho e a aplicação deve garantir que isso possa ser configurado.
5. Crie usuários específicos para executar tarefas da aplicação --e.g., banco de dados e sistema operacional.
6. Evite no sistema situações onde um usuário executar ações especiais e ele mesmo auditá-las --e.g., usuário executa a compra de um item e ele mesmo aprova a compra.


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
4. Lembre-se que é mais fácil tratar vulnerabilidades em ambientes de homologação do que nos seus pares de produção.
5. Separe fisica e logicamente os ambientes de homologação e produção.
6. Crie ambientes de homologação o mais parecidos possível dos seus pares de produção.
7. Proteja os ambientes de homologação com o mesmo nível dos de produção; caso eles tenham de ser expostos a partes não confiáveis, considere utilizar rotinas de mascaramento de dados --e.g., trocar números de CPF, embaralhar nomes e alterar endereços de email.


## 10. Outros
1. Garanta que o sistema esteja alinhado com a legislação local --e.g., [Marco Civil da Internet](https://www.planalto.gov.br/ccivil_03/_ato2011-2014/2014/lei/l12965.htm) e [SOX](https://en.wikipedia.org/wiki/Sarbanes%E2%80%93Oxley_Act).
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
Criado por José Lopes de Oliveira Jr. e licenciado sob a [GNU General Public License v3 ou posterior](https://github.com/forkd/seguranca/blob/master/LICENSE) --leia o arquivo `LICENSE` para mais informações.

### Contribuições
* Encontrou algum erro?
* Quer sugerir outra prática ou outro tópico?
* Quer relatar um caso de uso?
* Pintou alguma dúvida?

Entre em contato: `joselopes (a) cemig.com.br` **ou** submeta um *pull request*  **ou** abra uma nova *issue* aqui.

*Apenas a mudança é permanente.*

### Agradecimentos
* [Cemig](http://www.cemig.com.br)
* [Comunidade Python Brasil](http://python.org.br)
