# Cuidado ao importar módulos!  Tente usar apenas a biblioteca
# padrão da linguagem e módulos bem conhecidos, obtidos de
# fontes confiáveis.
from hashlib import pbkdf2_hmac
from base64 import b64encode, b64decode

import nacl.utils
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from nacl.secret import SecretBox
from argon2 import PasswordHasher
from otpauth import OtpAuth
from logging import basicConfig, warning
from OpenSSL.crypto import load_pkcs12, dump_certificate, FILETYPE_TEXT
from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive


class Criptografia(object):
    def __init__(self):
        """
        PYCRYPTO
        O PyCrypto provê um ótimo conjunto de funções criptográficas.  Para dar
        mais liberdade ao programador, essa biblioteca não entrega soluções
        prontas, o que exige do seu utilizador bons conhecimentos em
        criptografia e codificação segura.

        As funções pycrypto_enc e pycrypto_dec, por exemplo, utilizam o AES
        para [de]cifrar mensagens, mas exigem funções adicionais, para garantir
        que o tamanho total da mensagem seja múltiplo do tamanho de bloco
        usado --pad e unpad.

        Essas funções são aqui implementadas seguindo o padrão PKCS7, o que
        significa que são vulneráveis ao padding oracle attack.

        PYNACL
        Exemplos mais seguros ainda do uso de criptografia são mostrados nas
        funções pynacl_enc e pynacl_dec, que usam a biblioteca NaCl para
        [de]criptografar mensagens.  É importante perceber como é mais fácil
        usar essa biblioteca que a anterior, o que ajuda na segurança, mas
        diminui a liberdade do programador.  Apesar disso, é importante saber
        como essa biblioteca funciona, quais algoritmos ela utiliza e como
        eles estão implementados, visto que praticamente nada é exposto --o
        que é ótimo do ponto de vista de segurança.

        """
        # Adiciona dados no fim da mensagem, para completar o tamanho do bloco.
        self.pad = lambda s: s + (AES.block_size - len(s) % AES.block_size) * \
            chr(AES.block_size - len(s) % AES.block_size)

        # Retira os dados adicionados pela função anterior no fim da mensagem.
        self.unpad = lambda s: s[:-ord(s[-1:])]

        # Sal usado nas funções do PyNaCl - escolhi uma string e fiz o hash
        self.pynacl_sal = pbkdf2_hmac('sha256', b'Aquele S4l _ULTR4_ Sekr3t0!',
            b'Aquele S4l _ULTR4_ Sekr3t0!', 100000, SecretBox.KEY_SIZE)

    def pycrypto_enc(self, msg, chave):
        """
        Criptografa uma mensagem usando AES no modo CBC com PyCryto.

        ARGS:
        - msg (string): mensagem em si.
        - chave (string): chave para criptografar a mensagem.

        """
        chave = pbkdf2_hmac('sha256', chave.encode('utf8'), self.pynacl_sal,
            100000, SecretBox.KEY_SIZE)
        vi = Random.new().read(AES.block_size)
        cifra = AES.new(chave, AES.MODE_CBC, vi)
        return b64encode(vi + cifra.encrypt(self.pad(msg))).decode()

    def pycrypto_dec(self, cifrada, chave):
        """
        Decriptografa uma mensagem criptografada com o método anterior.

        ARGS:
        - cifrada (string): mensagem cifrada.
        - chave (string): chave para decriptografar a mensagem cifrada.

        """
        chave = pbkdf2_hmac('sha256', chave.encode('utf8'), self.pynacl_sal,
            100000, SecretBox.KEY_SIZE)
        cifrada = b64decode(cifrada)
        vi = cifrada[:16]
        cifra = AES.new(chave, AES.MODE_CBC, vi)
        return self.unpad(cifra.decrypt(cifrada[16:])).decode('utf8')

    def pynacl_enc(self, msg, chave):
        """
        Criptografa uma mensagem usando a biblioteca NaCl.

        ARGS:
        - msg (string): mensagem em si.
        - chave (string): chave para criptografar a mensagem.

        """
        chave = pbkdf2_hmac('sha256', chave.encode('utf8'), self.pynacl_sal,
            100000, SecretBox.KEY_SIZE)
        nonce = nacl.utils.random(SecretBox.NONCE_SIZE)
        return b64encode(SecretBox(chave).encrypt(msg.encode('utf8'),
            nonce)).decode()

    def pynacl_dec(self, cifrada, chave):
        """
        Decriptografa uma mensagem usando a NaCl.

        ARGS:
        - cifrada (string): mensagem cifrada.
        - chave (string): chave para decriptograr a mensagem cifrada.

        """
        chave = pbkdf2_hmac('sha256', chave.encode('utf8'), self.pynacl_sal,
            100000, SecretBox.KEY_SIZE)
        cifrada = b64decode(cifrada.encode('utf8'))
        return SecretBox(chave).decrypt(cifrada).decode()


class Senhas(object):
    def protege_senha_hmac_sha256(self, senha, sal, chave):
        """
        Protege a senha usando HMAC + SHA-256 + salt, como indicado pelo OWASP
        [1].

        ARGS:
        - senha (string): senha digitada pelo usuário.
        - sal (string): usada para "temperar" a senha, evitando ataques de
            dicionário.
            Ex.: 6b3a55e0261b030$143f805a24924dOc1c44524821305f31d927743b8a10f
        - chave (string): a chave usada para criptografar o hash.
            Ex.: a7998f247bd965694ff227fa325c81&69a07471a8B6808d3e002a486c4e65

        """
        # Crypto.Hash.HMAC exige o uso de bytes em vez de
        # strings --uma especificidade do Python 3.
        senha = senha.encode()
        chave = chave.encode()
        return sal + HMAC.new(sal.encode() + chave, senha, SHA256).hexdigest()

    def protege_senha_pbkdf2(self, senha, sal, iter):
        """
        Protege a senha usando o PBKDF2.

        ARGS:
        - senha (string): senha digitada pelo usuário.
        - sal (string): usada para "temperar a senha".
        - iter (integer): quantidade de iterações --o manual
            (hashlib.pbkdf2()), de 2013, recomenda, no mínimo, 100000.

        NOTA
        Em ambientes de produção, o parâmetro de iterações do PBKDF2 pode ser
        alterado, para garantir mais segurança --o manual da biblioteca usada
        aqui sugere valores maiores que 100000 (cem mil).

        """
        return b64encode(pbkdf2_hmac('sha256', senha.encode('utf8'),
            sal.encode('utf8'), iter)).decode('utf8')

    def protege_senha_argon2(self, senha):
        """
        O Argon2 foi vencedor da edição 2015 da 'Password Hashing Competition'
        <https://password-hashing.net> e é indicado por muitos especialistas
        como a melhor solução para hash de senhas.

        ARGS:
        - senha (string): senha digitada pelo usuário.

        NOTAS
        1. O resultado de um hash Argon2 informa os parâmetros usados para
            obter aquele hash, além do próprio hash.
        2. Em ambientes de produção, esses parâmetros podem ser melhor
            configurados, como o tempo e a memória utilizados.

        """
        return PasswordHasher().hash(senha)


class Autenticacao(object):
    def segundo_fator(self, metodo, chave):
        """
        Calcula e retorna one-time passwords para uso como segundo fator de
        autenticação baseados em tempo ou hashes criptografados.

        ARGS:
        - metodo (string): pode ser 'time' ou 'hmac'.
        - chave (string): a chave privada usada para gerar os códigos.

        """
        au = OtpAuth(chave)

        if metodo == 'time':
            return au.totp()
        elif metodo == 'hmac':
            return au.hotp()
        else:
            raise ValueError('método não identificado')


class Validacao(object):
    def codifica_b64(self, entrada):
        """
        Codifica a entrada do usuário em Base 64, para armazenagem segura.
        Retorna uma string com a representação hexadecimal da entrada.

        ARGS:
        - entrada (string): a string informada pelo usuário.

        """
        return b64encode(entrada.encode()).decode()

    def decodifica_b64(self, codificados):
        """
        Decodifica um dado que foi armazenado de forma codificada.  Retorna
        uma string com os dados decodificados.

        PARÂMETROS
        - codificados (string): string na sua representação Base 64.

        """
        return b64decode(codificados.encode()).decode()


class Transferencias(object):
    pass


class Logs(object):
    def __init__(self):
        basicConfig(format='%(asctime)s %(levelname)s: %(message)s')

    def log_aviso(self, msg):
        """
        Cria um log de aviso.

        ARGS:
        - msg (string): a mensagem a ser "logada".

        """
        warning(msg)

    def tamanho_log(self, eventos_dia, tamanho):
        """
        Calcula o tamanho médio para armazenagem dos logs de uma aplicação.

        ARGS:
        - eventos_dia (integer): média de eventos diários.
        - tamanho (integer): tamanho médio (bytes) do log de cada evento --1
            (um) caractere == 1 byte.

        """
        # 30 dias no mês + 10% do tamanho especificado; resultado em GB
        tamanho_mes = eventos_dia * 30 * (tamanho + (10 * tamanho /
            100)) * 10 ** -9

        return 'Tamanho em 1 mês..: {0:6.2f} GB\n'\
            'Tamanho em 6 meses: {1:6.2f} GB\n'\
            'Tamanho em 1 ano..: {2:6.2f} GB\n'\
            'Tamanho em 1,5 ano: {3:6.2f} GB\n'\
            'Tamanho em 2 anos.: {4:6.2f} GB\n'\
            'Tamanho em 5 anos.: {5:6.2f} GB'.format(tamanho_mes,
            tamanho_mes*6, tamanho_mes*12, tamanho_mes*18, tamanho_mes*24,
            tamanho_mes*60)


class CertificadosDigitais(object):
    def le_cert_p12(self, caminho, senha):
        p12 = load_pkcs12(open(caminho, 'rb').read(), senha)
        return dump_certificate(FILETYPE_TEXT, p12.get_certificate()).decode()


class SegregacaoFuncoes(object):
    pass


class Nuvem(object):
    def upload_para_gdrive(self, caminho):
        """
        Este método faz o upload de um arquivo para o Google Drive.  Para que
        funcione, siga os passos a seguir:

        a. Entre no Google Developers Console
            <https://console.developers.google.com>, com a sua conta no Google,
            crie um novo projeto e habilite o Google Drive.
        b. Após configurar o projeto e tê-lo criado, entre em 'Credentials',
            selecione o projeto recém criado, e em 'Download JSON'.
        c. Renomeie o arquivo baixado para 'client_secrets.json' e coloque-o
            no mesmo diretório deste script.
        d. Ao ser executado, este script usará os parâmetros definidos no
            arquivo JSON para autenticar essa aplicação; em seguida, será
            aberto um navegador, para que o usuário acesse sua conta no Google
            e dê permissões de acesso a esta aplicação.

        ARGS:
        - path (string): caminho do arquivo a ser 'subido' para o Google Drive.

        """
        f = GoogleDrive(GoogleAuth()).CreateFile()
        f.SetContentFile(caminho)
        f.Upload()


class TestesAnalisesVulnerabilidade(object):
    pass
