#!/usr/bin/env python3
"""
O Tao do Software Seguro
= === == ======== ======


Visão Geral
Este guia apresenta práticas de desenvolvimento seguro.  Cada capítulo foi
tratado como uma classe e alguns exemplos de aplicação foram implementados
como métodos.  Dessa forma, basta importar o módulo dentro do interpretador
Python e instanciar objetos de acordo com a necessidade.

Dica: use a ajuda embutida do interpretador Python para ler este documento.
Exemplo:
>>> import seguranca
>>> help(seguranca)
>>> c1 = seguranca.Capitulo1()
>>> help(c1)


Autor
José Lopes de Oliveira Jr. <joselopes _em_ cemig.com.br>


Licença
GNU General Public License v3 ou posterior (GPLv3+)


Referências
[ 1] Open Web Application Security Project (OWASP).  Password Storage Cheat
     Sheet.  Disponível em: <https://www.owasp.org/index.php/
     Password_Storage_Cheat_Sheet>.  Acesso em 13/07/2016.
[ 2] National Institute of Standards and Technology (NIST).  Recommendation for
     Block Cipher Modes of Operation.  NIST Special Publication 800-38A.  2001.
     Disponível em: <http://csrc.nist.gov/publications/nistpubs/800-38a/
     sp800-38a.pdf>. Acesso em 13/07/2016.
[ 3] Open Web Application Security Project (OWASP).  OWASP Proactive Controls.
     Disponível em: <https://www.owasp.org/index.php/OWASP_Proactive_Controls>.
     Acesso em 13/07/2016.
[ 4] Open Web Application Security Project (OWASP).  SQL Injection Prevention
     Cheat Sheet.  Disponível em: <https://www.owasp.org/index.php/
     SQL_Injection_Prevention_Cheat_Sheet>.  Acesso em 15/07/2016.
[ 5] Open Web Application Security Project (OWASP).  Session Management Cheat
     Sheet.  Disponível em: <https://www.owasp.org/index.php/Session_
     Management_Cheat_Sheet>.  Acesso em: 15/07/2016.

"""


# Cuidado ao importar módulos!  Tente usar apenas a biblioteca
# padrão da linguagem e módulos bem conhecidos, obtidos de
# fontes confiáveis.
from hashlib import md5  # usado apenas para fins didáticos
from base64 import b64encode, b64decode
from binascii import hexlify, unhexlify

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from otpauth import OtpAuth
from logging import basicConfig, warning
from OpenSSL.crypto import load_pkcs12, dump_certificate, FILETYPE_TEXT


class Capitulo0(object):
    """
    CRIPTOGRAFIA
    ------------

    0. *NUNCA* crie seu sistema criptográfico: use aqueles já existentes.
    1. Conheça os tipos mais comuns de criptografia --simétrica e assimétrica.
    2. Na criptografia simétrica, prefira usar o Advanced Encryption Standard
        (AES).
    3. Na criptografia assimétrica, prefira usar o Rivest, Shamir, Adleman
        (RSA) ou o Eliptic Curve Cryptography (ECC).
    4. Entenda o que são hashes e hashes criptografados.
    5. Evite usar o Message Digest 5 (MD5) ou o Secure Hash 1 (SHA-1) --prefira
        o SHA-256, por exemplo.
    6. Nas cifras de bloco, evite usar o modo Electronic Codebook (ECB)
        --prefira o Cipher Block Chaining (CBC).

    """
    def __init__(self):
        self.pad = lambda s: s + (AES.block_size - len(s) % AES.block_size) * \
            chr(AES.block_size - len(s) % AES.block_size)
        self.unpad = lambda s: s[:-ord(s[len(s) - 1:])]

    def aes_cbc_enc(self, msg, key):
        """
        Criptografa uma mensagem usando AES no modo CBC.

        PARÂMETROS
        - msg (string): mensagem em si.
        - key (string): chave para criptografar a mensagem.

        """
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(md5(key.encode('utf8')).hexdigest(), AES.MODE_CBC, iv)
        return b64encode(iv + cipher.encrypt(self.pad(msg)))

    def aes_cbc_dec(self, ciph, key):
        """
        Decriptografa uma mensagem criptografada com aes_cbc_enc().

        PARÂMETROS
        - ciph (string): mensagem cifrada.
        - key (string): chave para decriptografar a cifra.

        """
        ciph = b64decode(ciph)
        iv = ciph[:16]
        cipher = AES.new(md5(key.encode('utf8')).hexdigest(), AES.MODE_CBC, iv)
        return self.unpad(cipher.decrypt(ciph[16:])).decode('utf8')

class Capitulo1(object):
    """
    ARMAZENAMENTO DE SENHAS
    ------------- -- ------

    1. Não limite o conjunto de caracteres das senhas.
    2. Permita senhas realmente longas --e.g., 160 caracteres.
    3. Proteja as senhas antes de armazená-las --e.g., usando salt.
    4. Considere usar hashes criptográfados na proteção da senha.
    5. Trate os salts e as credenciais de hash como chaves privadas.
    6. Crie parâmetros mínimos de senha --e.g., 12 caracteres, com letras
        minúsculas, maiúsculas, números e não-alfanuméricos.

    """
    def protected_password(self, password, salt, key):
        """
        Prepara uma senha para ser armazenada/verificada.

        PARÂMETROS
        - password (string): senha digitada pelo usuário.
        - salt (string): usada para "temperar" a senha, evitando ataques
            de dicionário.
            Ex.: 6b3a55e0261b030$143f805a24924dOc1c44524821305f31d927743b8a10f
        - key (string): a chave usada para criptografar o hash.
            Ex.: a7998f247bd965694ff227fa325c81&69a07471a8B6808d3e002a486c4e65

        """
        # Crypto.Hash.HMAC exige o uso de bytes em vez de
        # strings --uma especificidade do Python 3.
        password = password.encode()
        key = key.encode()

        return salt + HMAC.new(salt.encode() + key, password,
            SHA256).hexdigest()

class Capitulo2(object):
    """
    AUTENTICAÇÃO
    ------------

    1. Sempre faça autenticação negativa: variáveis que permitirão a entrada
        devem ser inicializadas como False.
    2. Prefira usar sistemas de autenticação existentes --e.g., LDAP, Active
        Directory e OAuth.
    3. Mensagens de erro de autenticação devem informar o problema sem expor
        dados sensíveis, como nomes de usuário e versões de software.
    4. Sempre que possível, implemente o duplo fator de autenticação --RFCs
        4226 ou 6238.
    5. Atenção ao usar certificados digitais para autenticação: um sistema
        que use essa técnica deve abrir o certificado, baixar a CRL
        relacionada, verificar se o certificado em questão está lá, verificar
        a cadeia de emissão do certificado, obter o identificador do usuário
        gravado no certificado, verificar se aquele identificador está
        permitido a acessar o sistema e, só então, permitir o acesso.

    """
    def second_factor(self, method, key):
        """
        Calcula e retorna one-time passwords para uso como segundo fator de
        autenticação baseados em tempo ou hashes criptografados.

        PARÂMETROS
        - method (string): pode ser 'time' ou 'hmac'.
        - key (string): a chave privada usada para gerar os códigos.

        """
        auth = OtpAuth(key)

        if method == 'time':
            return auth.totp()
        elif method == 'hmac':
            return auth.hotp()
        else:
            raise ValueError('método não identificado')

class Capitulo3(object):
    """
    VALIDAÇÃO
    ---------

    1. Valide todos os dados de entrada adequadamente.
    2. Trate com atenção caracters especiais, como aspas simples e duplas.
    3. Preste atenção aos _ranges_ nos campos da sua aplicação --e.g., um campo
        para nome não deveria permitir o envio de 1024 caracteres.
    4. Em aplicações web, validações no lado cliente devem ser refeitas no
        servidor.
    5. Parametrize consultas SQL, use um mapeamento objeto-relacional (ORM) ou
        estude a utilização de stored procedures.
    6. Considere como dados de entrada cabeçalhos HTTP, parâmetros GET/POST,
       cookies e arquivos, por exemplo.
    7. Atenção aos cookies: evite armazenar dados sensíveis neles, defina uma
       data de expiração da sessão.


    """
    def hexencode(self, user_entry):
        """
        Codifica a entrada do usuário em hexadecimal, para armazenagem segura.

        PARÂMETROS
        - user_entry (string): a string informada pelo usuário.

        Retorna uma string com a representação hexadecimal da entrada.

        """
        return hexlify(user_entry.encode()).decode()

    def hexdecode(self, stored_data):
        """
        Decodifica um dado que foi armazenado de forma codificada.

        PARÂMETROS
        - stored_data (string): string na sua representação hexadecimal.

        Retorna uma string com os dados decodificados.

        """
        return unhexlify(stored_data.encode()).decode()


class Capitulo4(object):
    """
    TRANSFERÊNCIAS
    --------------

    1. Em aplicações web, use HTTPS em vez do HTTP.
    2. Prefira transferir arquivos via Secure Shell (SSH); evite FTP ou SMB.
    3. No servidor, desabilite versões inseguras de protocolos de criptografia
        --e.g., SSLv2 e SSLv3.
    4. Crie senhas fortes para os serviços e evite compartilhá-las.
    5. Considere criptografar todas as conexões que forem feitas pela
        aplicação --e.g., LDAP over TLS/SSL (LDAPS) e SNMPv3.

    """
    pass

class Capitulo5(object):
    """
    LOGS
    ----

    1. Defina informações importantes que precisam ser armazenadas para fins
        de auditoria.
    2. Considere usar bibliotecas específicas para a geração de logs.
    3. Estruture os logs de acordo com algum padrão; evite criar novos --e.g.,
        syslog-ng e ISO 8601 para datas.
    4. Projete seu sistema de logs considerando que ele eventualmente será
        exportado para um Security Information and Event Management (SIEM).
    5. *NUNCA* exponha informações sensíveis em logs --e.g., senhas.
    6. Lembre-se que haverá geração de logs em várias camadas; não reinvente a
        roda --e.g., uma aplicação web poderia guardar somente o que o usuário
        fez dentro do programa e quando; endereços IP e falhas de login
        poderiam estar nos logs do servidor web ou do sistema operacional.
    7. Mantenha os servidores atualizados de acordo com um serviço confiável e
        único dentro do domínio, para manter o padrão --e.g., ntp.br.
    8. Prefira armazenar datas de logs com o fuso GMT+0, ajustando o fuso
        apenas na apresentação para o auditor.
    9. Para facilitar futuras pesquisas, defina níveis de log padrões para sua
        aplicação --e.g., debug, info, warning, error e critical.

    """
    def __init__(self):
        basicConfig(format='%(asctime)s %(levelname)s: %(message)s')

    def warning_log(self, message):
        """
        Cria um log de aviso.

        PARÂMETROS
        - message (string): a mensagem a ser "logada".

        """
        warning(message)

    def log_size(self, epd, size):
        """
        Calcula o tamanho médio para armazenagem dos logs de uma aplicação.

        PARÂMETROS
        - epd (integer): média de eventos diários.
        - size (integer): tamanho médio (bytes) do log de cada evento --1 (um)
            caractere == 1 byte.

        """
        # 30 dias no mês + 10% do tamanho especificado; resultado em GB
        size_in_1_month = epd * 30 * (size + (10 * size / 100)) * 10 ** -9

        return 'Tamanho em 1 mês..: {0:6.2f} GB\n'\
            'Tamanho em 6 meses: {1:6.2f} GB\n'\
            'Tamanho em 1 ano..: {2:6.2f} GB\n'\
            'Tamanho em 1,5 ano: {3:6.2f} GB\n'\
            'Tamanho em 2 anos.: {4:6.2f} GB\n'\
            'Tamanho em 5 anos.: {5:6.2f} GB'.format(size_in_1_month,
            size_in_1_month*6, size_in_1_month*12, size_in_1_month*18,
            size_in_1_month*24, size_in_1_month*60)

class Capitulo6(object):
    """
    CERTIFICADOS DIGITAIS
    ------------ --------

    1. Ao usar certificados em software, tenha atenção a quem tem acesso ao
        servidor onde ele está instalado.
    2. De forma segura, remova do servidor certificados vencidos revogados ou
        inutilizados por quaisquer outros motivos.
    3. Mantenha algum tipo de controle de validade de certificados digitais,
        considerando que leva-se um tempo entre o pedido de renovação e a
        emissão do novo certificado --dependendo da morosidade do processo
        de aquisição do certificado, da criticidade e período de validade
        dele, considere renovar com 6 meses de antecedência.
    4. Evite usar um certificado para mais de uma finalidade --à exceção de
        certificados do tipo wildcard.
    5. Certificados wildcard devem receber atenção especial: o ideal é que
        seu 'instalador' seja restrito a poucas pessoas e servidores; o uso
        ideal dele seria em um proxy reverso, fechando conexões seguras com
        clientes e esse proxy fechando conexões seguras com os servidores
        usando outros certificados.

    """
    def read_p12(self, path, password):
        p12 = load_pkcs12(open(path, 'rb').read(), password)
        return dump_certificate(FILETYPE_TEXT, p12.get_certificate()).decode()

class Capitulo7(object):
    """
    Segregação de funções(?)
    """
    pass

class Capitulo8(object):
    """
    NUVEM
    -----

    0. Entenda que 'nuvem', no fundo, significa um servidor alocado em algum
        local remoto.
    1. Ao usar serviços 'na nuvem', procure saber mais sobre o provedor daquele
        serviço: casos de sucesso, clientes, garantias de segurança, backup,
        recuperação de desastres etc.
    2. Descubra onde, de fato, os dados serão armazenados ou processados; não
        se esqueça que cada país possui a sua legislação e ela pode afetar
        o seu serviço.

    """
    pass

class Capitulo9(object):
    """
    TESTES E ANÁLISES DE VULNERABILIDADE
    ------ - -------- -- ---------------

    1. Realize análises de vulnerabilidade periodicamente nas aplicações.
    2. Adicione uma etapa de análise de vulnerabilidades ao processo de
        desenvolvimento de software.
    3. Publique aplicações apenas após tratar todas as vulnerabilidades
        listadas nas análises.
    4. Lembre-se que é mais fácil tratar vulnerabilidades em ambientes de
        homologação do que produção.
    5. Separe fisica e logicamente os ambientes de homologação e produção.
    6. Crie ambientes de homologação o mais parecidos possível dos seus
        pares de produção.

    """
    pass
