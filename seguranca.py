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
from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive


class Criptografia(object):
    def __init__(self):
        """
        Cifras de bloco precisam processar arquivos cujos tamanhos sejam
        múltiplos do tamanho de bloco utilizado.

        A função pad adiciona dados ao final da mensagem, para garantir isso.
        A função unpad remove os dados adicionados.

        NOTA
        As funções de padding, são baseadas no padrão PKCS7 e usadas junto com
        o CBC.  Portanto, estão vulneráveis ao padding oracle attack.

        """
        self.pad = lambda s: s + (AES.block_size - len(s) % AES.block_size) * \
            chr(AES.block_size - len(s) % AES.block_size)
        self.unpad = lambda s: s[:-ord(s[-1:])]

    def criptografa(self, msg, chave):
        """
        Criptografa uma mensagem usando AES no modo CBC.

        ARGS:
        - msg (string): mensagem em si.
        - chave (string): chave para criptografar a mensagem.

        """
        vi = Random.new().read(AES.block_size)
        cifra = AES.new(md5(chave.encode('utf8')).hexdigest(), AES.MODE_CBC, vi)
        return b64encode(vi + cifra.encrypt(self.pad(msg)))

    def decriptografa(self, cifrada, chave):
        """
        Decriptografa uma mensagem criptografada com o método anterior.

        ARGS:
        - cifrada (string): mensagem cifrada.
        - chave (string): chave para decriptografar a cifra.

        """
        cifrada = b64decode(cifrada)
        vi = cifrada[:16]
        cifra = AES.new(md5(chave.encode('utf8')).hexdigest(), AES.MODE_CBC, vi)
        return self.unpad(cifra.decrypt(cifrada[16:])).decode('utf8')


class Senhas(object):
    def protege_senha(self, senha, sal, chave):
        """
        Prepara uma senha para ser armazenada/verificada.

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
    def codificahex(self, entrada):
        """
        Codifica a entrada do usuário em hexadecimal, para armazenagem segura.
        Retorna uma string com a representação hexadecimal da entrada.

        ARGS:
        - entrada (string): a string informada pelo usuário.

        """
        return hexlify(entrada.encode()).decode()

    def decodificahex(self, codificados):
        """
        Decodifica um dado que foi armazenado de forma codificada.  Retorna
        uma string com os dados decodificados.

        PARÂMETROS
        - codificados (string): string na sua representação hexadecimal.

        """
        return unhexlify(stored_data.encode()).decode()


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

        PARÂMETROS
        - path (string): caminho do arquivo a ser 'subido' para o Google Drive.

        """
        f = GoogleDrive(GoogleAuth()).CreateFile()
        f.SetContentFile(caminho)
        f.Upload()


class TestesAnalisesVulnerabilidade(object):
    pass
