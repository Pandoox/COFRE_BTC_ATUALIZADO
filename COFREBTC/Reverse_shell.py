import os
import json
import sys
import base64
import hashlib
import getpass
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Constantes de segurança
SALT_SIZE = 16
PBKDF2_ITERATIONS = 480000
NONCE_SIZE = 12
TAG_SIZE = 16
MAX_ATTEMPTS = 3
LOCK_TIME = 300  # 5 minutos em segundos

class BitcoinVault:
    def __init__(self):
        self.vault_data = {
            "electrum_seed": "",
            "addresses": [],
            "metadata": {
                "created": datetime.now().isoformat(),
                "last_access": ""
            }
        }
        self.attempts = 0
        self.locked_until = 0

    
    def self_destruct(self):
        """Remove os arquivos do cofre após múltiplas falhas"""
        print("\n🚨 ALERTA: Modo de autodestruição ativado!")

        try:
            if os.path.exists("vault.dat"):
                os.remove("vault.dat")
                print("🗑️ vault.dat removido.")

            if os.path.exists("recovery.dat"):
                os.remove("recovery.dat")
                print("🗑️ recovery.dat removido.")

            # Opcional: apagar backups também
            backup_folder = "backups"
            if os.path.exists(backup_folder):
                for file in os.listdir(backup_folder):
                    path = os.path.join(backup_folder, file)
                    os.remove(path)
                print("🧨 Backups destruídos.")

        except Exception as e:
            print(f"Erro durante autodestruição: {str(e)}")




    def derive_key(self, password: str, salt: bytes) -> bytes:
        """Deriva uma chave de 256 bits usando PBKDF2-HMAC-SHA512"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def encrypt_data(self, data: dict, password: str) -> tuple:
        """Criptografa dados com AES-256-GCM"""
        salt = os.urandom(SALT_SIZE)
        key = self.derive_key(password, salt)
        nonce = os.urandom(NONCE_SIZE)
        aesgcm = AESGCM(key)
        
        plaintext = json.dumps(data).encode()
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        
        return salt, nonce, ciphertext

    def decrypt_data(self, salt: bytes, nonce: bytes, ciphertext: bytes, password: str) -> dict:
        """Descriptografa dados com AES-256-GCM"""
        key = self.derive_key(password, salt)
        aesgcm = AESGCM(key)
        
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return json.loads(plaintext.decode())
        except Exception as e:
            raise ValueError("Falha na descriptografia - senha incorreta ou dados corrompidos")

    def save_vault(self, password: str):
        """Salva o cofre criptografado"""
        salt, nonce, ciphertext = self.encrypt_data(self.vault_data, password)
        
        with open("vault.dat", "wb") as f:
            f.write(salt + nonce + ciphertext)
        
        # Atualizar metadata
        self.vault_data["metadata"]["last_access"] = datetime.now().isoformat()

    def load_vault(self, password: str) -> bool:
        """Carrega o cofre criptografado"""
        if not os.path.exists("vault.dat"):
            return False
            
        with open("vault.dat", "rb") as f:
            data = f.read()
            
        if len(data) < SALT_SIZE + NONCE_SIZE + TAG_SIZE:
            raise ValueError("Tamanho do arquivo do cofre inválido")
            
        salt = data[:SALT_SIZE]
        nonce = data[SALT_SIZE:SALT_SIZE+NONCE_SIZE]
        ciphertext = data[SALT_SIZE+NONCE_SIZE:]
        
        try:
            self.vault_data = self.decrypt_data(salt, nonce, ciphertext, password)
            return True
        except ValueError as e:
            self.attempts += 1
            if self.attempts >= MAX_ATTEMPTS:
                self.locked_until = datetime.now().timestamp() + LOCK_TIME
            raise

    def setup_recovery_questions(self):
        """Configura perguntas de recuperação"""
        questions = []
        print("\n=== PERGUNTAS DE RECUPERAÇÃO ===")
        print("Configure 3 perguntas que só você sabe responder:")
        
        for i in range(1, 4):
            while True:
                question = input(f"\nPergunta {i}: ")
                answer = getpass.getpass(f"Resposta {i}: ")
                confirm = getpass.getpass("Confirme a resposta: ")
                
                if answer == confirm:
                    questions.append({
                        "question": question,
                        "answer_hash": hashlib.sha512(answer.encode()).hexdigest()
                    })
                    break
                print("As respostas não coincidem! Tente novamente.")
        
        # Criptografar perguntas com hash da senha
        recovery_key = hashlib.sha512(getpass.getpass("\nDigite sua senha novamente para criptografar as perguntas: ").encode()).digest()
        aesgcm = AESGCM(recovery_key[:32])
        nonce = os.urandom(NONCE_SIZE)
        ciphertext = aesgcm.encrypt(nonce, json.dumps(questions).encode(), None)
        
        with open("recovery.dat", "wb") as f:
            f.write(nonce + ciphertext)

    def verify_recovery(self, password: str) -> bool:
        """Verifica as perguntas de segurança"""
        if not os.path.exists("recovery.dat"):
            return False
            
        try:
            with open("recovery.dat", "rb") as f:
                data = f.read()
                
            nonce = data[:NONCE_SIZE]
            ciphertext = data[NONCE_SIZE:]
            
            recovery_key = hashlib.sha512(password.encode()).digest()
            aesgcm = AESGCM(recovery_key[:32])
            questions = json.loads(aesgcm.decrypt(nonce, ciphertext, None).decode())
            
            print("\n=== VERIFICAÇÃO DE SEGURANÇA ===")
            for q in questions:
                answer = getpass.getpass(f"{q['question']}: ")
                if hashlib.sha512(answer.encode()).hexdigest() != q["answer_hash"]:
                    return False
            return True
            
        except Exception:
            return False

    def create_vault(self):
        """Cria um novo cofre"""
        print("\n=== NOVO COFRE BITCOIN ===")
        
        # Definir senha forte
        while True:
            password = getpass.getpass("Crie uma SENHA FORTE (mínimo 16 caracteres): ")
            if len(password) < 16:
                print("A senha deve ter pelo menos 16 caracteres!")
                continue
                
            confirm = getpass.getpass("Confirme a senha: ")
            if password == confirm:
                break
            print("As senhas não coincidem!")
        
        # Configurar seed e endereços
        print("\n=== CONFIGURAÇÃO DA CARTEIRA ===")
        while True:
            seed = getpass.getpass("Digite suas 12 palavras-semente (separadas por espaços): ")
            if len(seed.split()) == 12:
                self.vault_data["electrum_seed"] = seed
                break
            print("Deve conter exatamente 12 palavras!")
        
        # Adicionar endereços
        print("\n=== ENDEREÇOS BITCOIN ===")
        while True:
            addr = input("Digite um endereço (ou deixe em branco para terminar): ").strip()
            if not addr:
                break
            self.vault_data["addresses"].append(addr)
        
        # Configurar perguntas de recuperação
        self.setup_recovery_questions()
        
        # Salvar cofre
        self.save_vault(password)
        print("\nCofre criado com sucesso! Guarde suas informações com segurança.")

    def access_vault(self):
        """Acessa o cofre existente com dupla autenticação"""
        current_time = datetime.now().timestamp()
        if current_time < self.locked_until:
            remaining = int((self.locked_until - current_time) / 60)
            print(f"\nCofre bloqueado! Tente novamente em {remaining} minutos.")
            return
            
        print("\n=== ACESSO AO COFRE ===")
        password = getpass.getpass("Digite sua senha: ")
        
        try:
            if not self.load_vault(password):
                print("Nenhum cofre encontrado. Crie um novo cofre.")
                return
                
            # Verificação obrigatória das perguntas
            print("\n=== VERIFICAÇÃO DE SEGURANÇA ===")
            if not self.verify_recovery(password):
                print("\nRespostas incorretas! Acesso negado.")
                self.attempts += 1
                if self.attempts >= MAX_ATTEMPTS:
                    print("⚠️ Muitas tentativas falhas. Ativando protocolo de autodestruição!")
                    self.self_destruct()
                    return

                
            print("\nAcesso autorizado! Verificação completa.")
            self.show_menu(password)
            
        except ValueError as e:
            print(f"\nERRO: {str(e)}")
            remaining_attempts = MAX_ATTEMPTS - self.attempts
            if remaining_attempts > 0:
                print(f"Tentativas restantes: {remaining_attempts}")
            else:
                print("⚠️ Tentativas excedidas. Ativando protocolo de autodestruição!")
                self.self_destruct()
            


    def show_menu(self, password: str):
        """Menu principal"""
        while True:
            print("\n=== MENU PRINCIPAL ===")
            print("1. Ver palavras-semente")
            print("2. Listar endereços")
            print("3. Adicionar endereço")
            print("4. Alterar senha")
            print("5. Backup do cofre")
            print("6. Sair")
            
            choice = input("Escolha: ").strip()
            
            if choice == "1":
                print("\n=== PALAVRAS-SEMENTE ===")
                print(self.vault_data["electrum_seed"])
                input("\nPressione Enter para continuar...")
                
            elif choice == "2":
                print("\n=== ENDEREÇOS ===")
                for addr in self.vault_data["addresses"]:
                    print(f"- {addr}")
                    
            elif choice == "3":
                addr = input("\nNovo endereço: ").strip()
                if addr:
                    self.vault_data["addresses"].append(addr)
                    self.save_vault(password)
                    print("Endereço adicionado com sucesso!")
                    
            elif choice == "4":
                self.change_password(password)
                
            elif choice == "5":
                self.create_backup(password)
                
            elif choice == "6":
                print("Cofre bloqueado com segurança.")
                break

    def change_password(self, old_password: str):
        """Altera a senha do cofre"""
        print("\n=== ALTERAR SENHA ===")
        new_password = getpass.getpass("Nova senha (mínimo 16 caracteres): ")
        if len(new_password) < 16:
            print("A senha deve ter pelo menos 16 caracteres!")
            return
            
        confirm = getpass.getpass("Confirme a nova senha: ")
        if new_password != confirm:
            print("As senhas não coincidem!")
            return
            
        # Re-criptografar com nova senha
        self.save_vault(new_password)
        print("Senha alterada com sucesso!")

    def create_backup(self, password: str):
        """Cria backup do cofre"""
        backup_name = input("\nNome do backup (sem extensão): ").strip()
        if not backup_name:
            print("Operação cancelada.")
            return
            
        if not os.path.exists("vault.dat"):
            print("Nenhum cofre encontrado para backup!")
            return
            
        # Criar diretório de backups se não existir
        os.makedirs("backups", exist_ok=True)
        
        try:
            # Copiar arquivos essenciais
            import shutil
            shutil.copy2("vault.dat", f"backups/{backup_name}.vault")
            if os.path.exists("recovery.dat"):
                shutil.copy2("recovery.dat", f"backups/{backup_name}.recovery")
            print(f"Backup criado em: backups/{backup_name}.*")
        except Exception as e:
            print(f"Erro ao criar backup: {str(e)}")

    def recover_vault(self):
        """Recupera acesso via perguntas de segurança"""
        print("\n=== RECUPERAÇÃO DE ACESSO ===")
        password = getpass.getpass("Digite sua senha atual (ou deixe em branco se não lembra): ")
        
        if password and self.verify_recovery(password):
            print("\nIdentidade verificada!")
            new_password = getpass.getpass("Crie uma nova senha: ")
            if len(new_password) >= 16:
                self.save_vault(new_password)
                print("Senha redefinida com sucesso!")
                return
            else:
                print("Senha muito curta!")
                return
                
        print("\nRecuperação falhou. Opções:")
        print("1. Tentar novamente")
        print("2. Criar novo cofre com seed phrase")
        choice = input("Escolha: ").strip()
        
        if choice == "1":
            self.recover_vault()
        elif choice == "2":
            if input("Você tem suas 12 palavras-semente? (s/n): ").lower() == 's':
                self.create_vault()

def main():
    vault = BitcoinVault()
    
    while True:
        print("\n=== COFRE BITCOIN SEGURO ===")
        print("1. Criar novo cofre")
        print("2. Acessar cofre existente")
        print("3. Recuperar acesso")
        print("4. Sair")
        
        choice = input("Escolha: ").strip()
        
        if choice == "1":
            vault.create_vault()
        elif choice == "2":
            vault.access_vault()
        elif choice == "3":
            vault.recover_vault()
        elif choice == "4":
            print("Até logo!")
            break
        else:
            print("Opção inválida!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperação cancelada pelo usuário.")
    except Exception as e:
        print(f"\nERRO CRÍTICO: {str(e)}")
        print("Recomendação: Verifique seus arquivos de backup.")