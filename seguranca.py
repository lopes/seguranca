#!/usr/bin/env python3
"""
O Tao do Software Seguro
- --- -- -------- ------


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


class Capitulo0(object):
    """
    Criptografia

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

        :param msg: string - mensagem em si.
        :param key: string - chave para criptografar a mensagem.

        """
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(md5(key.encode('utf8')).hexdigest(), AES.MODE_CBC, iv)
        return b64encode(iv + cipher.encrypt(self.pad(msg)))

    def aes_cbc_dec(self, ciph, key):
        """
        Decriptografa uma mensagem criptografada com aes_cbc_enc().

        :param ciph: string - mensagem cifrada.
        :param key: string - chave para decriptografar a cifra.

        """
        ciph = b64decode(ciph)
        iv = ciph[:16]
        cipher = AES.new(md5(key.encode('utf8')).hexdigest(), AES.MODE_CBC, iv)
        return self.unpad(cipher.decrypt(ciph[16:])).decode('utf8')

class Capitulo1(object):
    """
    Armazenamento de Senhas

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
        :param password: string - senha digitada pelo usuário.
        :param salt: string - usada para "temperar" a senha, evitando ataques
            de dicionário.
            Ex.: 6b3a55e0261b030$143f805a24924dOc1c44524821305f31d927743b8a10f
        :param key: a chave usada para criptografar o hash.
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
    Autenticação

    1. Sempre faça autenticação negativa: variáveis que permitirão a entrada
        devem ser inicializadas como False.
    2. Prefira usar sistemas de autenticação existentes --e.g., LDAP, Active
        Directory e OAuth.
    3. Mensagens de erro de autenticação devem informar o problema sem expor
        dados sensíveis, como nomes de usuário e versões de software.
    4. Sempre que possível, implemente o duplo fator de autenticação --RFCs
        4226 ou 6238.

    """
    def second_factor(self, method, key):
        """
        Calcula e retorna one-time passwords para uso como segundo fator de
        autenticação baseados em tempo ou hashes criptografados.

        :param method: string - pode ser 'time' ou 'hmac'.
        :param key: string - a chave privada usada para gerar os códigos.

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
    Validação

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

        :param user_entry: string - a string informada pelo usuário.

        Retorna uma string com a representação hexadecimal da entrada.

        """
        return hexlify(user_entry.encode()).decode()

    def hexdecode(self, stored_data):
        """
        Decodifica um dado que foi armazenado de forma codificada.

        :param stored_data: string - string na sua representação hexadecimal.

        Retorna uma string com os dados decodificados.

        """
        return unhexlify(stored_data.encode()).decode()


class Capitulo4(object):
    """
    Transferências

    1. Em aplicações web, use HTTPS em vez do HTTP.
    2. Prefira transferir arquivos via Secure Shell (SSH); evite FTP ou SMB.
    3. No servidor, desabilite versões inseguras de protocolos de criptografia
        --e.g., SSLv2 e SSLv3.
    4. Para compartilhamento de arquivos via rede evite

    """
    pass

class Capitulo5(object):
    """
    Logs

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

        :param message: string - a mensagem a ser "logada".

        """
        warning(message)

class Capitulo6(object):
    pass

class Capitulo7(object):
    pass

class Capitulo8(object):
    pass

class Capitulo9(object):
    """
    Análise de Vulnerabilidade

    1. Realize análises de vulnerabilidade periodicamente nas aplicações.
    2. Adicione uma etapa de análise de vulnerabilidades ao processo de
        desenvolvimento de software.
    3. Publique aplicações apenas após tratar todas as vulnerabilidades
        listadas nas análises.
    4. Lembre-se que é mais fácil tratar vulnerabilidades em ambientes de
        homologação do que produção.

    """
    pass
