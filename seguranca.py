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

"""

# Cuidado ao importar módulos!  Tente usar apenas a biblioteca
# padrão da linguagem e módulos bem conhecidos, obtidos de
# fontes confiáveis.
from hashlib import md5  # usado apenas para fins didáticos
from base64 import b64encode, b64decode

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256

from otpauth import OtpAuth


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
            Ex.: a7998f247bd965694ff227fa325c81&69a07471a8B6808d3e002a486c4e659

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
        o usuário --e.g.,
    4. Sempre que possível, implemente o duplo fator de autenticação --RFCs
        4226 ou 6238.

    """
    def second_factor(self, method, key):
        """
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

    Valide todos os dados de entrada adequadamente.
    Caracteres de escape, como ' e " devem ser adequadamente tratados.
    Preste atenção aos ranges nos campos da sua aplicação.
    Em aplicações web, validações no lado cliente devem ser refeitas no servidor.

    """
    pass

class Capitulo4(object):
    """
    Transferências

    Em aplicações web, use HTTPS em vez do HTTP.
    Prefira transferir arquivos via SSH.

    """
    pass

class Capitulo5(object):
    pass

class Capitulo6(object):
    pass

class Capitulo7(object):
    pass

class Capitulo8(object):
    pass

class Capitulo9(object):
    """
    Análise de Vulnerabilidade

    Realize análises de vulnerabilidade periodicamente nas aplicações.
    Adicione uma etapa de análise de vulnerabilidades ao processo de
    desenvolvimento de software.
    Publique aplicações apenas após tratar todas as vulnerabilidades listadas
    nas análises.
    Lembre-se que é mais fácil tratar vulnerabilidades em ambientes de
    homologação do que produção.

    """
    pass
