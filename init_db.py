import os
import sqlite3
from bcrypt import hashpw, gensalt

def reset_database():
    """Supprime l'ancienne base de données et recrée les tables."""
    if os.path.exists('database.db'):
        os.remove('database.db')
        print("Base de données supprimée.")
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    create_tables(cursor)
    
    hashed_password = hashpw('password'.encode('utf-8'), gensalt()).decode('utf-8')
    cursor.execute('INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)',
                   ('admin_fab', hashed_password, 'fabricant', 'admin@example.com'))
    
    conn.commit()
    conn.close()
    print("Base de données réinitialisée avec succès.")

def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Check if the 'phone' column exists, and add it if it doesn't
    cursor.execute("PRAGMA table_info(users)")
    columns = [column[1] for column in cursor.fetchall()]
    if 'phone' not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN phone TEXT NOT NULL DEFAULT ''")

    # Create tables if they don't exist
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
    # Other table creation logic...
    conn.commit()
    conn.close()
    print("Base de données initialisée avec succès.")

def create_tables(cursor):
    """Crée toutes les tables nécessaires."""
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            phone TEXT NOT NULL DEFAULT ''
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS serrures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nom TEXT NOT NULL,
            admin_client_id INTEGER,
            code_ouverture TEXT CHECK(length(code_ouverture) = 6),
            FOREIGN KEY (admin_client_id) REFERENCES users (id)
        )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS tags (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nom_proprietaire TEXT NOT NULL,
        code_tag TEXT NOT NULL,
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
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tag_id INTEGER,
            serrure_id INTEGER,
            date_ouverture TEXT NOT NULL,
            FOREIGN KEY (tag_id) REFERENCES tags (id),
            FOREIGN KEY (serrure_id) REFERENCES serrures (id)
        )
    ''')

if __name__ == "__main__":
    reset_database()
