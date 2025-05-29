import os
import sqlite3
from bcrypt import hashpw, gensalt

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def execute_with_retry(conn, query, params=()):
    try:
        conn.execute(query, params)
    except sqlite3.OperationalError as e:
        if "database is locked" in str(e):
            import time
            time.sleep(0.1)
            conn.execute(query, params)
        else:
            raise

def reset_database():
    """Supprime l'ancienne base de données et recrée les tables."""
    if os.path.exists('database.db'):
        os.remove('database.db')
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    create_tables(cursor)
    
    hashed_password = hashpw('password'.encode('utf-8'), gensalt()).decode('utf-8')
    cursor.execute('INSERT INTO users (username, password, role, email, phone) VALUES (?, ?, ?, ?, ?)',
                  ('admin_fab', hashed_password, 'fabricant', 'admin@example.com', '+1234567890'))
    
    conn.commit()
    conn.close()

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    create_tables(cursor)
    
    # Vérifier si l'admin fabricant existe déjà
    admin = cursor.execute('SELECT * FROM users WHERE username = ?', ('admin_fab',)).fetchone()
    if not admin:
        # Créer l'admin fabricant par défaut
        hashed_password = hashpw('password'.encode('utf-8'), gensalt()).decode('utf-8')
        cursor.execute('INSERT INTO users (username, password, role, email, phone) VALUES (?, ?, ?, ?, ?)',
                      ('admin_fab', hashed_password, 'fabricant', 'admin@example.com', '+1234567890'))
    
    conn.commit()
    conn.close()
    print("Base de données initialisée avec succès.")

def create_tables(cursor):
    # Création des utilisateurs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT NOT NULL CHECK(length(phone) >= 10)
        )
    ''')
    
    # Création des serrures
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS serrures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nom TEXT NOT NULL,
            admin_client_id INTEGER,
            code_ouverture TEXT CHECK(length(code_ouverture) = 6),
            FOREIGN KEY (admin_client_id) REFERENCES users (id)
        )
    ''')
    
    # Création des tags
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tags (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nom_proprietaire TEXT NOT NULL,
            code_tag TEXT NOT NULL CHECK(length(code_tag) >= 4),
            date_debut TEXT NOT NULL,
            date_fin TEXT NOT NULL,
            jours_autorises TEXT NOT NULL,
            horaire_debut TEXT NOT NULL,
            horaire_fin TEXT NOT NULL,
            etat TEXT NOT NULL CHECK(etat IN ('autorisé', 'non autorisé')),
            serrure_id INTEGER,
            FOREIGN KEY (serrure_id) REFERENCES serrures (id)
        )
    ''')
    
    # Création des actions
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tag_id INTEGER,
            serrure_id INTEGER,
            date_ouverture TEXT NOT NULL,
            resultat TEXT,
            FOREIGN KEY (tag_id) REFERENCES tags (id),
            FOREIGN KEY (serrure_id) REFERENCES serrures (id)
        )
    ''')
    
    # Création de la table pour les adresses MAC
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS locks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id INTEGER NOT NULL,
            mac_address TEXT NOT NULL UNIQUE,
            lock_name TEXT NOT NULL,
            FOREIGN KEY (client_id) REFERENCES users (id)
        )
    ''')

if __name__ == "__main__":
    init_db()
    print("Base de données initialisée.")
