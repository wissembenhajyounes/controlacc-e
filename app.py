from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3
from bcrypt import hashpw, gensalt, checkpw
import re
import datetime
import logging
from flask_cors import CORS
import time
from collections import defaultdict
import threading

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('app.log')
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)
app.secret_key = 'votre_clé_secrète'

# Variables pour la protection contre les attaques par force brute
failed_attempts = defaultdict(int)  # Nombre d'échecs par adresse IP
attempt_timestamps = defaultdict(list)  # Horodatages des tentatives par adresse IP
locked_ips = {}  # IPs bloquées avec timestamp de déblocage
MAX_FAILED_ATTEMPTS = 5  # Nombre maximum de tentatives échouées avant blocage
LOCK_DURATION = 300  # Durée de blocage en secondes (5 minutes)
ATTEMPT_WINDOW = 600  # Fenêtre de temps pour considérer les tentatives (10 minutes)

# Verrou pour protéger les structures de données partagées
lock = threading.Lock()

# Fonction pour nettoyer les tentatives anciennes
def cleanup_old_attempts():
    now = time.time()
    with lock:
        for ip in list(attempt_timestamps.keys()):
            # Supprimer les tentatives qui sont plus anciennes que la fenêtre
            attempt_timestamps[ip] = [t for t in attempt_timestamps[ip] if now - t < ATTEMPT_WINDOW]
            
            # Si plus aucune tentative récente, réinitialiser le compteur
            if not attempt_timestamps[ip]:
                del attempt_timestamps[ip]
                if ip in failed_attempts:
                    del failed_attempts[ip]
                    
        # Supprimer les IP dont le blocage est expiré
        expired_locks = [ip for ip, unlock_time in locked_ips.items() if now > unlock_time]
        for ip in expired_locks:
            del locked_ips[ip]
            logger.info(f"IP {ip} débloquée après période de blocage")

# Démarrer un thread pour nettoyer périodiquement
def start_cleanup_thread():
    def cleanup_task():
        while True:
            cleanup_old_attempts()
            time.sleep(60)  # Exécuter toutes les minutes
            
    thread = threading.Thread(target=cleanup_task, daemon=True)
    thread.start()

# Connexion à la base de données
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.execute('PRAGMA journal_mode=WAL;')  # Active le mode WAL
    conn.row_factory = sqlite3.Row
    return conn

# Nouvelle route pour visualiser les données
@app.route('/visualiser_donnees', methods=['GET'])
def visualiser_donnees():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()

    # Récupérer les données de toutes les tables
    users = conn.execute('SELECT * FROM users').fetchall()
    serrures = conn.execute('SELECT * FROM serrures').fetchall()
    tags = conn.execute('SELECT * FROM tags').fetchall()
    actions = conn.execute('SELECT * FROM actions').fetchall()

    logger.info(f"Actions récupérées : {actions}")

    conn.close()

    # Passer les données au template
    return render_template('visualiser_donnees.html', 
                           users=users, 
                           serrures=serrures, 
                           tags=tags, 
                           actions=actions)

# Fonction pour exécuter des requêtes avec gestion des erreurs de verrouillage
def execute_with_retry(conn, query, params=(), retries=5):
    for attempt in range(retries):
        try:
            return conn.execute(query, params)
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e):
                time.sleep(0.1)  # Attendre un peu avant de réessayer
            else:
                raise
    raise Exception("Database is still locked after multiple attempts")

# Initialisation de la base de données
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Supprimer l'ancienne table actions si elle existe pour éviter les conflits de schéma
    cursor.execute('DROP TABLE IF EXISTS actions')
    
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
    # Insertion d'un admin fabricant par défaut
    hashed_password = hashpw('password'.encode('utf-8'), gensalt()).decode('utf-8')
    execute_with_retry(conn, 'INSERT OR IGNORE INTO users (username, password, role, email, phone) VALUES (?, ?, ?, ?, ?)',
                       ('admin_fab', hashed_password, 'fabricant', 'admin@example.com', '+1234567890'))
    conn.commit()
    conn.close()
    print("Base de données initialisée avec succès.")

# Page de connexion
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            session['user_id'] = user['id']
            session['role'] = user['role']
            if user['role'] == 'fabricant':
                return redirect(url_for('admin_fabricant'))
            elif user['role'] == 'client':
                return redirect(url_for('admin_client', user_id=user['id']))
        else:
            flash('Identifiants incorrects')
    return render_template('login.html')

# Page admin fabricant
@app.route('/admin_fabricant', methods=['GET', 'POST'])
def admin_fabricant():
    if 'user_id' not in session or session['role'] != 'fabricant':
        return redirect(url_for('login'))

    conn = get_db_connection()

    # Ajouter un admin client
    if request.method == 'POST' and 'add_client' in request.form:
        logger.info(f"Form submission received: {request.form}")
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        phone = request.form['phone']

        # Check for duplicate username
        existing_user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if existing_user:
            flash('Ce nom d\'utilisateur existe déjà. Veuillez en choisir un autre.', 'error')
        elif len(password) < 8:
            flash('Le mot de passe doit contenir au moins 8 caractères.', 'error')
        elif not re.match(r'^\+?[0-9]{10,15}$', phone):
            flash('Veuillez fournir un numéro de téléphone valide (10 à 15 chiffres).', 'error')
        else:
            hashed_password = hashpw(password.encode('utf-8'), gensalt()).decode('utf-8')
            try:
                execute_with_retry(conn, 'INSERT INTO users (username, password, role, email, phone) VALUES (?, ?, ?, ?, ?)',
                                   (username, hashed_password, 'client', email, phone))
                conn.commit()
                flash('Compte client créé avec succès.', 'success')
            except sqlite3.IntegrityError:
                flash('Erreur lors de la création du compte client.', 'error')

    # Supprimer un admin client
    if 'delete_client' in request.args:
        client_id = request.args.get('delete_client')
        execute_with_retry(conn, 'DELETE FROM users WHERE id = ?', (client_id,))
        conn.commit()
        flash('Compte client supprimé avec succès.', 'success')

    clients = conn.execute('SELECT * FROM users WHERE role = ?', ('client',)).fetchall()
    conn.close()
    return render_template('admin_fabricant.html', clients=clients)

# Page configurer serrure avec RFID
@app.route('/configurer_rfid/<int:user_id>', methods=['GET', 'POST'])
def configurer_rfid(user_id):
    if 'user_id' not in session or session['role'] != 'client':
        return redirect(url_for('login'))

    conn = get_db_connection()

    # Récupérer les serrures du client pour le menu déroulant
    serrures = conn.execute('SELECT * FROM serrures WHERE admin_client_id = ?', (user_id,)).fetchall()

    if request.method == 'POST' and 'add_serrure_rfid' in request.form:
        nom_proprietaire = request.form['nom_proprietaire']
        code_tag = request.form['code_tag']
        serrure_id = request.form.get('serrure_id')  # Récupérer l'ID de la serrure sélectionnée

        if not serrure_id:
            flash('Veuillez sélectionner une serrure.', 'error')
        elif re.match(r'^[0-9A-Fa-f]{4,}$', code_tag):  # Vérifier le format du code RFID/NFC
            try:
                # Vérifier si le tag existe déjà
                existing_tag = conn.execute('SELECT * FROM tags WHERE code_tag = ?', (code_tag,)).fetchone()
                if existing_tag:
                    flash('Ce tag RFID existe déjà.', 'error')
                else:
                    # Ajouter le tag avec l'ID de la serrure associée
                    execute_with_retry(conn, '''
                        INSERT INTO tags (nom_proprietaire, code_tag, date_debut, date_fin, jours_autorises, horaire_debut, horaire_fin, etat, serrure_id)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (nom_proprietaire, code_tag, '2025-01-01', '2025-12-31', 'Lundi,Mardi,Mercredi,Jeudi,Vendredi', '08:00', '18:00', 'autorisé', serrure_id))
                    conn.commit()
                    flash('Tag RFID ajouté avec succès.', 'success')
            except sqlite3.IntegrityError as e:
                flash(f'Erreur : {str(e)}', 'error')
        else:
            flash('Veuillez fournir un code de tag RFID valide (au moins 4 caractères hexadécimaux).', 'error')
        conn.close()
        return redirect(url_for('admin_client', user_id=user_id))

    conn.close()
    return render_template('configurer_rfid.html', serrures=serrures, user_id=user_id)

# Page configurer serrure avec Code PIN
@app.route('/configurer_pin/<int:user_id>', methods=['GET', 'POST'])
def configurer_pin(user_id):
    if 'user_id' not in session or session['role'] != 'client':
        return redirect(url_for('login'))

    if request.method == 'POST' and 'add_serrure_pin' in request.form:
        nom_serrure = request.form['nom_serrure']
        code_ouverture = request.form['code_ouverture']
        conn = get_db_connection()

        if re.match(r'^\d{6}$', code_ouverture):  # Validate the PIN code format
            try:
                # Add the lock directly to the `serrures` table
                execute_with_retry(conn, '''
                    INSERT INTO serrures (nom, admin_client_id, code_ouverture)
                    VALUES (?, ?, ?)
                ''', (nom_serrure, user_id, code_ouverture))
                conn.commit()
                flash('Serrure avec code PIN ajoutée avec succès.', 'success')
            except sqlite3.IntegrityError:
                flash('Erreur : la serrure avec ce code PIN existe déjà.', 'error')
        else:
            flash('Veuillez fournir un code PIN valide (6 chiffres).', 'error')
        conn.close()
        return redirect(url_for('admin_client', user_id=user_id))

    return render_template('configurer_pin.html')

# Page ouvrir serrure avec Code PIN
@app.route('/ouvrir_serrure/<int:user_id>', methods=['POST'])
def ouvrir_serrure(user_id):
    code_ouverture = request.form['code_ouverture']
    serrure_id = request.form['serrure_id']
    conn = get_db_connection()
    serrure = conn.execute('SELECT * FROM serrures WHERE id = ? AND code_ouverture = ?', (serrure_id, code_ouverture)).fetchone()

    if serrure:
        execute_with_retry(conn, 'INSERT INTO actions (serrure_id, date_ouverture, resultat) VALUES (?, datetime("now"), ?)', 
                           (serrure_id, "Accès autorisé"))
        conn.commit()
        flash('Serrure ouverte avec succès.', 'success')
    else:
        execute_with_retry(conn, 'INSERT INTO actions (serrure_id, date_ouverture, resultat) VALUES (?, datetime("now"), ?)', 
                           (serrure_id, "Accès refusé"))
        conn.commit()
        flash('Code incorrect ou serrure non trouvée.', 'error')
    conn.close()
    return redirect(url_for('admin_client', user_id=user_id))

# Page admin client
@app.route('/admin_client/<int:user_id>', methods=['GET', 'POST'])
def admin_client(user_id):
    if 'user_id' not in session or session['role'] != 'client':
        return redirect(url_for('login'))

    conn = get_db_connection()

    # Récupérer les informations du client
    client = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

    if not client:
        conn.close()
        flash('Client introuvable.', 'error')
        return redirect(url_for('login'))

    # Récupérer les serrures du client
    serrures = conn.execute('SELECT * FROM serrures WHERE admin_client_id = ?', (user_id,)).fetchall()

    # Récupérer tous les tags du client
    tags = conn.execute('''
        SELECT tags.*, users.username AS nom_proprietaire
        FROM tags
        LEFT JOIN serrures ON tags.serrure_id = serrures.id
        LEFT JOIN users ON serrures.admin_client_id = users.id
        WHERE serrures.admin_client_id = ? OR tags.serrure_id IS NULL
    ''', (user_id,)).fetchall()
    tags = [dict(tag) for tag in tags]

    # Récupérer l'historique des actions en utilisant une requête simplifiée
    # Récupérer TOUTES les actions, puis filtrer dans Python plutôt qu'avec SQL complexe
    actions = conn.execute('SELECT * FROM actions').fetchall()
    actions_list = []
    
    # Traiter chaque action pour ajouter les informations nécessaires
    for action in actions:
        action_dict = dict(action)
        
        # Récupérer les informations de tag si tag_id existe
        if action['tag_id']:
            tag = conn.execute('SELECT * FROM tags WHERE id = ?', (action['tag_id'],)).fetchone()
            if tag:
                action_dict['tag_code'] = tag['code_tag']
                
                # Vérifier si le tag est associé à une serrure appartenant à ce client
                serrure = conn.execute('SELECT * FROM serrures WHERE id = ? AND admin_client_id = ?', 
                                      (tag['serrure_id'], user_id)).fetchone()
                if serrure:
                    action_dict['serrure_nom'] = serrure['nom']
                    actions_list.append(action_dict)
        
        # Récupérer les informations de serrure si serrure_id existe
        elif action['serrure_id']:
            serrure = conn.execute('SELECT * FROM serrures WHERE id = ?', (action['serrure_id'],)).fetchone()
            if serrure and serrure['admin_client_id'] == user_id:
                action_dict['serrure_nom'] = serrure['nom']
                actions_list.append(action_dict)
        
        # Pour les actions sans tag_id ni serrure_id (tentatives avec codes inconnus)
        # Afficher toutes ces actions pour le moment, pour fins de débogage
        else:
            action_dict['serrure_nom'] = "Inconnu"
            action_dict['tag_code'] = "Inconnu"
            # On ajoute toutes les actions pour le moment, à des fins de débogage
            actions_list.append(action_dict)
    
    logger.info(f"Actions récupérées pour le client {user_id}: {len(actions_list)}")
    for action in actions_list:
        logger.info(f"Action: {action}")
    
    # Remplacer la liste d'actions par notre liste traitée
    actions = actions_list

    conn.close()

    # Transmettre les données au template
    return render_template('admin_client.html', client=client, serrures=serrures, tags=tags, actions=actions)

# Modifier un tag
@app.route('/modifier_tag/<int:tag_id>', methods=['GET', 'POST'])
def modifier_tag(tag_id):
    if 'user_id' not in session or session['role'] != 'client':
        return redirect(url_for('login'))

    conn = get_db_connection()
    tag = conn.execute('SELECT * FROM tags WHERE id = ?', (tag_id,)).fetchone()

    if not tag:
        conn.close()
        flash('Tag non trouvé', 'error')
        return redirect(url_for('admin_client', user_id=session['user_id']))

    if request.method == 'POST':
        nom_proprietaire = request.form['nom_proprietaire']
        date_debut = request.form['date_debut']
        date_fin = request.form['date_fin']
        jours_autorises = request.form.getlist('jours_autorises')
        horaire_debut = request.form['horaire_debut']
        horaire_fin = request.form['horaire_fin']
        etat = request.form['etat']

        try:
            execute_with_retry(conn, '''
                UPDATE tags
                SET nom_proprietaire = ?, date_debut = ?, date_fin = ?, jours_autorises = ?, horaire_debut = ?, horaire_fin = ?, etat = ?
                WHERE id = ?
            ''', (nom_proprietaire, date_debut, date_fin, ','.join(jours_autorises), horaire_debut, horaire_fin, etat, tag_id))
            conn.commit()
            flash('Tag modifié avec succès', 'success')
        except sqlite3.IntegrityError as e:
            flash(f'Erreur : {str(e)}', 'error')
        finally:
            conn.close()
        return redirect(url_for('admin_client', user_id=session['user_id']))

    conn.close()
    return render_template('modifier_tag.html', tag=tag)

# Modifier un tag ou un code PIN
@app.route('/modifier/<string:type>/<int:item_id>', methods=['GET', 'POST'])
def modifier(type, item_id):
    if 'user_id' not in session or session['role'] != 'client':
        return redirect(url_for('login'))

    conn = get_db_connection()

    # Vérifiez si vous modifiez un tag ou un code PIN
    if type == 'tag':
        item = conn.execute('SELECT * FROM tags WHERE id = ?', (item_id,)).fetchone()
        if not item:
            conn.close()
            flash('Tag non trouvé.', 'error')
            return redirect(url_for('admin_client', user_id=session['user_id']))
    elif type == 'pin':
        item = conn.execute('SELECT * FROM serrures WHERE id = ?', (item_id,)).fetchone()
        if not item:
            conn.close()
            flash('Serrure non trouvée.', 'error')
            return redirect(url_for('admin_client', user_id=session['user_id']))
    else:
        conn.close()
        flash('Type de modification invalide.', 'error')
        return redirect(url_for('admin_client', user_id=session['user_id']))

    if request.method == 'POST':
        if type == 'tag':
            # Mise à jour des données du tag
            nom_proprietaire = request.form['nom_proprietaire']
            date_debut = request.form['date_debut']
            date_fin = request.form['date_fin']
            jours_autorises = request.form.getlist('jours_autorises')
            horaire_debut = request.form['horaire_debut']
            horaire_fin = request.form['horaire_fin']
            etat = request.form['etat']

            try:
                conn.execute('''
                    UPDATE tags
                    SET nom_proprietaire = ?, date_debut = ?, date_fin = ?, jours_autorises = ?, horaire_debut = ?, horaire_fin = ?, etat = ?
                    WHERE id = ?
                ''', (nom_proprietaire, date_debut, date_fin, ','.join(jours_autorises), horaire_debut, horaire_fin, etat, item_id))
                conn.commit()
                flash('Tag modifié avec succès.', 'success')
            except sqlite3.IntegrityError as e:
                flash(f'Erreur : {str(e)}', 'error')

        elif type == 'pin':
            # Mise à jour du code PIN et de ses paramètres
            new_code = request.form['code_ouverture']
            nom_proprietaire = request.form['nom_proprietaire']
            date_debut = request.form['date_debut']
            date_fin = request.form['date_fin']
            jours_autorises = request.form.getlist('jours_autorises')
            horaire_debut = request.form['horaire_debut']
            horaire_fin = request.form['horaire_fin']
            etat = request.form['etat']

            if not re.match(r'^\d{6}$', new_code):  # Vérifier le format du code PIN
                flash('Erreur : Le code PIN doit contenir exactement 6 chiffres.', 'error')
            else:
                try:
                    conn.execute('''
                        UPDATE serrures 
                        SET code_ouverture = ?, nom_proprietaire = ?, date_debut = ?, date_fin = ?, 
                            jours_autorises = ?, horaire_debut = ?, horaire_fin = ?, etat = ?
                        WHERE id = ?
                    ''', (new_code, nom_proprietaire, date_debut, date_fin, ','.join(jours_autorises), horaire_debut, horaire_fin, etat, item_id))
                    conn.commit()
                    flash('Code PIN et paramètres modifiés avec succès.', 'success')
                except sqlite3.IntegrityError as e:
                    flash(f'Erreur : {str(e)}', 'error')

        conn.close()
        return redirect(url_for('admin_client', user_id=session['user_id']))

    conn.close()
    return render_template('modifier_tag.html', item=item, type=type)

# Supprimer un tag
@app.route('/supprimer_tag/<int:tag_id>', methods=['GET'])
def supprimer_tag(tag_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    try:
        conn.execute('DELETE FROM tags WHERE id = ?', (tag_id,))
        conn.commit()
        flash('Tag RFID/NFC supprimé avec succès.', 'success')
    except sqlite3.IntegrityError:
        flash('Erreur lors de la suppression du tag RFID/NFC.', 'error')
    finally:
        conn.close()

    return redirect(url_for('admin_client', user_id=session['user_id']))

# Supprimer une serrure
@app.route('/supprimer_serrure/<int:serrure_id>', methods=['GET'])
def supprimer_serrure(serrure_id):
    if 'user_id' not in session or session['role'] != 'client':
        return redirect(url_for('login'))

    conn = get_db_connection()
    execute_with_retry(conn, 'DELETE FROM serrures WHERE id = ?', (serrure_id,))
    conn.commit()
    conn.close()
    flash('Serrure supprimée avec succès')
    return redirect(url_for('admin_client', user_id=session['user_id']))

# Supprimer un code PIN
@app.route('/supprimer_code_pin/<int:serrure_id>', methods=['GET'])
def supprimer_code_pin(serrure_id):
    if 'user_id' not in session or session['role'] != 'client':
        return redirect(url_for('login'))

    conn = get_db_connection()
    try:
        # Delete the PIN code from the `serrures` table
        execute_with_retry(conn, 'DELETE FROM serrures WHERE id = ?', (serrure_id,))
        conn.commit()
        flash('Code PIN supprimé avec succès.', 'success')
    except sqlite3.IntegrityError:
        flash('Erreur lors de la suppression du code PIN.', 'error')
    finally:
        conn.close()

    return redirect(url_for('admin_client', user_id=session['user_id']))

# Modifier un code PIN
@app.route('/modifier_code_pin/<int:serrure_id>', methods=['GET', 'POST'])
def modifier_code_pin(serrure_id):
    if 'user_id' not in session or session['role'] != 'client':
        return redirect(url_for('login'))

    conn = get_db_connection()
    serrure = conn.execute('SELECT * FROM serrures WHERE id = ? AND admin_client_id = ?', (serrure_id, session['user_id'])).fetchone()

    if not serrure:
        conn.close()
        flash('Serrure non trouvée.', 'error')
        return redirect(url_for('admin_client', user_id=session['user_id']))

    if request.method == 'POST':
        new_code = request.form['code_ouverture']

        if not re.match(r'^\d{6}$', new_code):  # Vérifier le format du code PIN
            flash('Erreur : Le code PIN doit contenir exactement 6 chiffres.', 'error')
        else:
            try:
                conn.execute('UPDATE serrures SET code_ouverture = ? WHERE id = ?', (new_code, serrure_id))
                conn.commit()
                flash('Code PIN modifié avec succès.', 'success')
            except sqlite3.IntegrityError as e:
                flash(f'Erreur : {str(e)}', 'error')
        conn.close()
        return redirect(url_for('admin_client', user_id=session['user_id']))

    conn.close()
    return render_template('modifier_code_pin.html', serrure=serrure)

# Supprimer une action
@app.route('/supprimer_action/<int:action_id>', methods=['GET'])
def supprimer_action(action_id):
    if 'user_id' not in session or session['role'] != 'client':
        return redirect(url_for('login'))

    conn = get_db_connection()
    try:
        conn.execute('DELETE FROM actions WHERE id = ?', (action_id,))
        conn.commit()
        flash('Action supprimée avec succès.', 'success')
    except sqlite3.IntegrityError:
        flash('Erreur lors de la suppression de l\'action.', 'error')
    finally:
        conn.close()

    return redirect(url_for('admin_client', user_id=session['user_id']))

# Déconnexion
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Vérifier l'accès avec l'UID de la carte RFID ou le code PIN
@app.route('/verifier_acces', methods=['GET'])
def verifier_acces():
    # Déclarez explicitement que vous utilisez la variable globale lock
    global lock
    
    logger.info("Requête reçue pour vérifier l'accès")
    card_id = request.args.get('card_id')
    code_pin = request.args.get('code_pin')
    mac_address = request.args.get('mac_address', '').upper()  # Récupérer l'adresse MAC
    
    logger.info(f"card_id: {card_id}, code_pin: {code_pin}, mac_address: {mac_address}")
    
    # Récupérer l'adresse IP
    ip_address = request.remote_addr
    current_time = time.time()
    
    # Si l'adresse MAC n'est pas fournie, refuser l'accès
    if not mac_address:
        logger.warning("Tentative d'accès sans adresse MAC")
        return jsonify({
            "status": "UNAUTHORIZED",
            "message": "Adresse MAC non fournie",
            "code": 403
        }), 403
    
    # Vérifier l'adresse MAC
    conn = get_db_connection()
    lock_info = conn.execute('SELECT * FROM locks WHERE mac_address = ?', (mac_address,)).fetchone()
    
    if not lock_info:
        logger.warning(f"Adresse MAC non reconnue: {mac_address}")
        if 'conn' in locals():
            conn.close()
        return jsonify({
            "status": "UNAUTHORIZED",
            "message": "Adresse MAC non reconnue",
            "code": 403
        }), 403
    
    # Récupérer l'ID du client associé à cette adresse MAC
    client_id = lock_info['client_id']
    logger.info(f"Adresse MAC {mac_address} associée au client ID: {client_id}")
    
    # Vérifier si l'adresse IP est bloquée
    with lock:
        if ip_address in locked_ips and current_time < locked_ips[ip_address]:
            remaining_time = int(locked_ips[ip_address] - current_time)
            logger.warning(f"Tentative d'accès bloquée pour l'IP {ip_address}. Bloqué pour encore {remaining_time} secondes.")
            if 'conn' in locals():
                conn.close()
            return jsonify({
                "status": "BLOCKED",
                "message": f"Trop de tentatives échouées. Réessayez dans {remaining_time} secondes.",
                "code": 429
            }), 429

    try:
        if not card_id and not code_pin:
            logger.error("No identifier provided in access verification request")
            if 'conn' in locals():
                conn.close()
            return jsonify({
                "status": "BAD_REQUEST",
                "message": "Aucun identifiant fourni",
                "code": 400
            }), 400
        
        # Date et heure actuelles avec fuseau horaire ajusté
        current_datetime = datetime.datetime.now() + datetime.timedelta(hours=0)
        timestamp = current_datetime.strftime("%Y-%m-%d %H:%M:%S")

        # Fonction pour convertir le jour actuel en français
        def convert_day_to_french(day):
            days_en_to_fr = {
                'Monday': 'Lundi',
                'Tuesday': 'Mardi',
                'Wednesday': 'Mercredi',
                'Thursday': 'Jeudi',
                'Friday': 'Vendredi',
                'Saturday': 'Samedi',
                'Sunday': 'Dimanche'
            }
            return days_en_to_fr.get(day, day)

        current_day = current_datetime.strftime('%A')  # Jour en anglais
        current_day_fr = convert_day_to_french(current_day).lower()  # Convertir en français et mettre en minuscule

        # Fonction pour gérer les échecs d'authentification
        def handle_auth_failure(reason):
            with lock:
                # Enregistrer la tentative
                attempt_timestamps[ip_address].append(current_time)
                failed_attempts[ip_address] += 1
                
                # Vérifier si l'IP doit être bloquée
                if failed_attempts[ip_address] >= MAX_FAILED_ATTEMPTS:
                    locked_ips[ip_address] = current_time + LOCK_DURATION
                    logger.warning(f"IP {ip_address} bloquée pour {LOCK_DURATION} secondes après {failed_attempts[ip_address]} tentatives échouées.")
                    
                    # Enregistrer l'action de blocage
                    execute_with_retry(conn, '''
                        INSERT INTO actions (tag_id, serrure_id, date_ouverture, resultat)
                        VALUES (?, ?, ?, ?)
                    ''', (None, None, timestamp, f"IP {ip_address} bloquée après {failed_attempts[ip_address]} tentatives échouées"))
                    conn.commit()
                    
                    return jsonify({
                        "status": "BLOCKED",
                        "message": f"Trop de tentatives échouées. Réessayez dans {LOCK_DURATION} secondes.",
                        "code": 429
                    }), 429
            
            # Si l'IP n'est pas encore bloquée, retourner l'erreur d'authentification normale
            logger.warning(f"Tentative échouée pour l'IP {ip_address}: {reason}. Compteur: {failed_attempts[ip_address]}")
            return jsonify({
                "status": "UNAUTHORIZED",
                "message": reason,
                "code": 403
            }), 403

        if card_id:
            # Validate card_id format
            if not re.match(r'^[0-9A-Fa-f]{4,}$', card_id):
                logger.warning(f"Invalid card_id format: {card_id}")
                execute_with_retry(conn, '''
                    INSERT INTO actions (tag_id, serrure_id, date_ouverture, resultat)
                    VALUES (?, ?, ?, ?)
                ''', (None, None, timestamp, f"Accès refusé - Format de tag RFID invalide: {card_id}"))
                conn.commit()
                return handle_auth_failure("Format de tag RFID invalide")

            tag = conn.execute('SELECT * FROM tags WHERE code_tag = ?', (card_id,)).fetchone()
            if not tag:
                logger.warning(f"Tag not found in database: {card_id}")
                execute_with_retry(conn, '''
                    INSERT INTO actions (tag_id, serrure_id, date_ouverture, resultat)
                    VALUES (?, ?, ?, ?)
                ''', (None, None, timestamp, f"Accès refusé - Tag non trouvé: {card_id}"))
                conn.commit()
                return handle_auth_failure("Tag non trouvé")
            
            # Vérifier que le tag appartient à une serrure de ce client
            serrure = conn.execute('SELECT * FROM serrures WHERE id = ?', (tag['serrure_id'],)).fetchone()
            if not serrure or serrure['admin_client_id'] != client_id:
                logger.warning(f"Tag {card_id} doesn't belong to client {client_id} or serrure doesn't exist")
                execute_with_retry(conn, '''
                    INSERT INTO actions (tag_id, serrure_id, date_ouverture, resultat)
                    VALUES (?, ?, ?, ?)
                ''', (tag['id'], tag['serrure_id'], timestamp, f"Accès refusé - Ce tag n'appartient pas à la serrure associée à cette adresse MAC"))
                conn.commit()
                return handle_auth_failure("Ce tag n'appartient pas à cette serrure")

            # Normaliser les jours autorisés
            jours_autorises = [jour.strip().lower() for jour in tag['jours_autorises'].split(',')]

            # Vérifier les conditions d'accès
            access_checks = [
                (tag['etat'] == 'autorisé', "Tag non autorisé"),
                (datetime.datetime.strptime(tag['date_debut'], '%Y-%m-%d').date() <= current_datetime.date() <= datetime.datetime.strptime(tag['date_fin'], '%Y-%m-%d').date(), "Hors période autorisée"),
                (current_day_fr in jours_autorises, "Jour non autorisé"),
                (datetime.datetime.strptime(tag['horaire_debut'], '%H:%M').time() <= current_datetime.time() <= datetime.datetime.strptime(tag['horaire_fin'], '%H:%M').time(), "Hors horaire autorisé")
            ]

            for condition, error_message in access_checks:
                if not condition:
                    logger.warning(f"Access denied for tag {card_id}: {error_message}")
                    execute_with_retry(conn, '''
                        INSERT INTO actions (tag_id, serrure_id, date_ouverture, resultat)
                        VALUES (?, ?, ?, ?)
                    ''', (tag['id'], tag['serrure_id'], timestamp, f"Accès refusé - {error_message}"))
                    conn.commit()
                    return handle_auth_failure(error_message)

            # Réinitialiser le compteur d'échecs pour cette IP après une authentification réussie
            with lock:
                if ip_address in failed_attempts:
                    del failed_attempts[ip_address]
                if ip_address in attempt_timestamps:
                    del attempt_timestamps[ip_address]

            # Enregistrer l'action dans la base de données
            execute_with_retry(conn, '''
                INSERT INTO actions (tag_id, serrure_id, date_ouverture, resultat)
                VALUES (?, ?, ?, ?)
            ''', (tag['id'], tag['serrure_id'], timestamp, "Accès autorisé"))
            conn.commit()
            logger.info(f"Access granted for tag: {card_id}")
            return jsonify({
                "status": "AUTHORIZED",
                "message": "Accès autorisé",
                "code": 200
            }), 200

        elif code_pin:
            # Validate PIN format
            if not re.match(r'^\d{6}$', code_pin):
                logger.warning(f"Invalid PIN format: {code_pin}")
                execute_with_retry(conn, '''
                    INSERT INTO actions (serrure_id, date_ouverture, resultat)
                    VALUES (?, ?, ?)
                ''', (None, timestamp, f"Accès refusé - Format de code PIN invalide: {code_pin}"))
                conn.commit()
                return handle_auth_failure("Format de code PIN invalide")

            serrure = conn.execute('SELECT * FROM serrures WHERE code_ouverture = ?', (code_pin,)).fetchone()
            if not serrure:
                logger.warning(f"Incorrect PIN code provided: {code_pin}")
                execute_with_retry(conn, '''
                    INSERT INTO actions (serrure_id, date_ouverture, resultat)
                    VALUES (?, ?, ?)
                ''', (None, timestamp, f"Accès refusé - Code PIN incorrect: {code_pin}"))
                conn.commit()
                return handle_auth_failure("Code PIN incorrect")
            
            # Vérifier que le code PIN appartient à une serrure de ce client
            if serrure['admin_client_id'] != client_id:
                logger.warning(f"PIN {code_pin} doesn't belong to client {client_id}")
                execute_with_retry(conn, '''
                    INSERT INTO actions (serrure_id, date_ouverture, resultat)
                    VALUES (?, ?, ?)
                ''', (serrure['id'], timestamp, f"Accès refusé - Ce code PIN n'appartient pas à la serrure associée à cette adresse MAC"))
                conn.commit()
                return handle_auth_failure("Ce code PIN n'appartient pas à cette serrure")
                
            # Maintenant, vérifier les conditions d'accès comme pour les tags RFID
            # Vérifier si la serrure a les nouveaux champs configurés
            has_new_fields = 'nom_proprietaire' in dict(serrure) and 'date_debut' in dict(serrure) and 'date_fin' in dict(serrure) and \
                             'jours_autorises' in dict(serrure) and 'horaire_debut' in dict(serrure) and 'horaire_fin' in dict(serrure) and \
                             'etat' in dict(serrure)
            
            if has_new_fields:
                # Vérifier si les champs sont nulls ou non définis
                if serrure['jours_autorises'] and serrure['date_debut'] and serrure['date_fin'] and \
                   serrure['horaire_debut'] and serrure['horaire_fin'] and serrure['etat']:
                    
                    # Normaliser les jours autorisés
                    jours_serrure = [jour.strip().lower() for jour in serrure['jours_autorises'].split(',')]
                    
                    # Vérifier les conditions d'accès
                    pin_access_checks = [
                        (serrure['etat'] == 'autorisé', "Code PIN non autorisé"),
                        (datetime.datetime.strptime(serrure['date_debut'], '%Y-%m-%d').date() <= current_datetime.date() <= 
                         datetime.datetime.strptime(serrure['date_fin'], '%Y-%m-%d').date(), "Hors période autorisée"),
                        (current_day_fr in jours_serrure, "Jour non autorisé"),
                        (datetime.datetime.strptime(serrure['horaire_debut'], '%H:%M').time() <= 
                         current_datetime.time() <= datetime.datetime.strptime(serrure['horaire_fin'], '%H:%M').time(), "Hors horaire autorisé")
                    ]
                    
                    for condition, error_message in pin_access_checks:
                        if not condition:
                            logger.warning(f"Access denied for PIN {code_pin}: {error_message}")
                            execute_with_retry(conn, '''
                                INSERT INTO actions (serrure_id, date_ouverture, resultat)
                                VALUES (?, ?, ?)
                            ''', (serrure['id'], timestamp, f"Accès refusé - {error_message}"))
                            conn.commit()
                            return handle_auth_failure(error_message)

            # Réinitialiser le compteur d'échecs pour cette IP après une authentification réussie
            with lock:
                if ip_address in failed_attempts:
                    del failed_attempts[ip_address]
                if ip_address in attempt_timestamps:
                    del attempt_timestamps[ip_address]

            # Si tout est OK ou si les nouveaux champs ne sont pas présents, autoriser l'accès
            execute_with_retry(conn, '''
                INSERT INTO actions (serrure_id, date_ouverture, resultat)
                VALUES (?, ?, ?)
            ''', (serrure['id'], timestamp, "Accès autorisé"))
            conn.commit()
            logger.info(f"Access granted via PIN code: {code_pin}")
            return jsonify({
                "status": "AUTHORIZED",
                "message": "Accès autorisé",
                "code": 200
            }), 200

    except Exception as e:
        logger.error(f"Error in access verification: {str(e)}")
        try:
            # Enregistrer l'erreur interne
            if 'conn' in locals():
                execute_with_retry(conn, '''
                    INSERT INTO actions (tag_id, serrure_id, date_ouverture, resultat)
                    VALUES (?, ?, ?, ?)
                ''', (None, None, timestamp, f"Erreur interne du serveur: {str(e)}"))
                conn.commit()
        except Exception as inner_e:
            logger.error(f"Error recording error: {str(inner_e)}")
            
        return jsonify({
            "status": "ERROR",
            "message": "Erreur interne du serveur",
            "code": 500
        }), 500
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/create_client', methods=['GET'])
def create_client():
    if 'user_id' not in session or session['role'] != 'fabricant':
        return redirect(url_for('login'))
    return render_template('create_client.html')

@app.route('/create_client', methods=['POST'])
def create_client_post():
    if 'user_id' not in session or session['role'] != 'fabricant':
        return redirect(url_for('login'))
    
    # Récupérer les données du formulaire
    username = request.form['username']
    password = request.form['password']
    confirm_password = request.form['confirm_password']
    email = request.form['email']
    phone = request.form['phone']
    mac_address = request.form['mac_address'].upper()
    lock_name = request.form['lock_name']
    
    # Validation côté serveur
    if password != confirm_password:
        flash('Les mots de passe ne correspondent pas.', 'error')
        return redirect(url_for('create_client'))
    
    conn = get_db_connection()
    
    try:
        # Vérifier si le nom d'utilisateur existe déjà
        existing_user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if existing_user:
            flash('Ce nom d\'utilisateur existe déjà. Veuillez en choisir un autre.', 'error')
            return redirect(url_for('create_client'))
        
        # Vérifier si la table locks existe
        table_exists = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='locks'").fetchone()
        if not table_exists:
            # Si la table n'existe pas, la créer
            conn.execute('''
                CREATE TABLE IF NOT EXISTS locks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id INTEGER NOT NULL,
                    mac_address TEXT NOT NULL UNIQUE,
                    lock_name TEXT NOT NULL,
                    FOREIGN KEY (client_id) REFERENCES users (id)
                )
            ''')
            conn.commit()
            logger.info("Table 'locks' créée car elle n'existait pas")
        
        # Vérifier si l'adresse MAC existe déjà
        existing_mac = conn.execute('SELECT * FROM locks WHERE mac_address = ?', (mac_address,)).fetchone()
        if existing_mac:
            flash('Cette adresse MAC est déjà associée à un client. Chaque client doit avoir une adresse MAC unique.', 'error')
            return redirect(url_for('create_client'))
        
        # Validation des données
        if len(password) < 8:
            flash('Le mot de passe doit contenir au moins 8 caractères.', 'error')
            return redirect(url_for('create_client'))
        
        if not re.match(r'^\+?[0-9]{10,15}$', phone):
            flash('Veuillez fournir un numéro de téléphone valide (10 à 15 chiffres).', 'error')
            return redirect(url_for('create_client'))
        
        if not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac_address):
            flash('Format d\'adresse MAC invalide. Utilisez le format AA:BB:CC:DD:EE:FF', 'error')
            return redirect(url_for('create_client'))
        
        # Hashage du mot de passe
        hashed_password = hashpw(password.encode('utf-8'), gensalt()).decode('utf-8')
        
        # Transaction pour assurer que l'utilisateur et l'adresse MAC sont créés ensemble
        conn.execute('BEGIN TRANSACTION')
        
        # Insérer le nouvel utilisateur
        conn.execute('''
            INSERT INTO users (username, password, role, email, phone) 
            VALUES (?, ?, ?, ?, ?)
        ''', (username, hashed_password, 'client', email, phone))
        
        # Récupérer l'ID du nouvel utilisateur
        user_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        
        # Associer l'adresse MAC à cet utilisateur
        conn.execute('''
            INSERT INTO locks (client_id, mac_address, lock_name)
            VALUES (?, ?, ?)
        ''', (user_id, mac_address, lock_name))
        
        conn.commit()
        
        flash('Compte client créé avec succès et adresse MAC associée.', 'success')
        logger.info(f"Nouveau client créé: {username} avec adresse MAC: {mac_address}")
        
    except sqlite3.IntegrityError as e:
        if conn:
            conn.rollback()
        flash(f'Erreur lors de la création du compte client: {str(e)}', 'error')
        logger.error(f"Erreur lors de la création du client: {str(e)}")
        
    except Exception as e:
        if conn:
            conn.rollback()
        flash(f'Une erreur inattendue s\'est produite: {str(e)}', 'error')
        logger.error(f"Exception lors de la création du client: {str(e)}")
        
    finally:
        if conn:
            conn.close()
        
    return redirect(url_for('admin_fabricant'))

@app.route('/modify_client')
def modify_client():
    return render_template('modify_client.html')

@app.route('/list_clients')
def list_clients():
    if 'user_id' not in session or session['role'] != 'fabricant':
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    
    # Récupérer les clients avec leurs adresses MAC associées
    clients_with_locks = conn.execute('''
        SELECT u.id, u.username, u.email, u.phone, l.mac_address, l.lock_name
        FROM users u
        LEFT JOIN locks l ON u.id = l.client_id
        WHERE u.role = 'client'
        ORDER BY u.username
    ''').fetchall()
    
    conn.close()
    
    return render_template('list_clients.html', clients=clients_with_locks)

@app.route('/modify_client', methods=['POST'])
def modify_client_post():
    username = request.form['username']
    new_password = request.form['new_password']
    conn = get_db_connection()

    # Check if the username exists
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    if not user:
        flash('Utilisateur non trouvé.', 'error')
    else:
        hashed_password = hashpw(new_password.encode('utf-8'), gensalt()).decode('utf-8')
        try:
            execute_with_retry(conn, 'UPDATE users SET password = ? WHERE username = ?', (hashed_password, username))
            conn.commit()
            flash('Mot de passe modifié avec succès.', 'success')
        except sqlite3.IntegrityError:
            flash('Erreur lors de la modification du mot de passe.', 'error')
    conn.close()
    return redirect(url_for('admin_fabricant'))

@app.route('/add_rfid', methods=['POST'])
def add_rfid():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    try:
        serrure_name = request.form['serrure_name']
        code_rfid = request.form['code_rfid']

        # Vérifier si la serrure existe
        serrure = conn.execute('SELECT * FROM serrures WHERE nom = ? AND admin_client_id = ?', (serrure_name, session['user_id'])).fetchone()
        if not serrure:
            flash('Erreur : La serrure spécifiée n\'existe pas.', 'error')
        elif not re.match(r'^[0-9A-Fa-f]{4,}$', code_rfid):  # Vérifier le format du code RFID/NFC
            flash('Erreur : Le code RFID/NFC doit contenir au moins 4 caractères hexadécimaux.', 'error')
        else:
            # Insérer le code RFID/NFC dans la base de données
            execute_with_retry(conn, '''
                INSERT INTO tags (nom_proprietaire, code_tag, serrure_id, date_debut, date_fin, jours_autorises, horaire_debut, horaire_fin, etat)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (serrure_name, code_rfid, serrure['id'], '2025-01-01', '2025-12-31', 'Lundi,Mardi,Mercredi,Jeudi,Vendredi', '08:00', '18:00', 'autorisé'))
            conn.commit()
            logger.info(f"Tag RFID/NFC ajouté : {serrure_name}, {code_rfid}")
            flash('Code RFID/NFC ajouté avec succès.', 'success')
    except sqlite3.IntegrityError as e:
        logger.error(f"Erreur lors de l'ajout du tag RFID/NFC : {str(e)}")
        flash('Erreur lors de l\'ajout du code RFID/NFC. Veuillez réessayer.', 'error')
    finally:
        conn.close()

    return redirect(url_for('admin_client', user_id=session['user_id']))

@app.route('/add_pin', methods=['POST'])
def add_pin():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    try:
        pin_owner = request.form['pin_owner']
        pin_code = request.form['pin_code']

        # Vérifier si un code PIN existe déjà pour cette serrure
        existing_pin = conn.execute('SELECT * FROM serrures WHERE nom = ? AND admin_client_id = ?', (pin_owner, session['user_id'])).fetchone()
        if existing_pin:
            flash('Erreur : Un code PIN existe déjà pour cette serrure.', 'error')
        elif not re.match(r'^\d{6}$', pin_code):  # Vérifier le format du code PIN
            flash('Erreur : Le code PIN doit contenir exactement 6 chiffres.', 'error')
        else:
            # Insérer le code PIN dans la base de données
            execute_with_retry(conn, '''
                INSERT INTO serrures (nom, admin_client_id, code_ouverture)
                VALUES (?, ?, ?)
            ''', (pin_owner, session['user_id'], pin_code))
            conn.commit()
            flash('Code PIN ajouté avec succès.', 'success')
    except sqlite3.IntegrityError:
        flash('Erreur lors de l\'ajout du code PIN. Veuillez réessayer.', 'error')
    finally:
        conn.close()

    return redirect(url_for('admin_client', user_id=session['user_id']))

# Afficher la structure de la table actions
@app.route('/table_info_actions', methods=['GET'])
def table_info_actions():
    conn = get_db_connection()
    try:
        # Récupérer les informations sur la table actions
        columns = conn.execute("PRAGMA table_info(actions);").fetchall()
        column_names = [column['name'] for column in columns]

        # Récupérer toutes les actions
        actions = conn.execute('SELECT * FROM actions').fetchall()

        # Passer les données au template
        return render_template('table_info_actions.html', columns=column_names, actions=actions)
    except Exception as e:
        flash(f'Erreur lors de la récupération des informations de la table actions : {str(e)}', 'error')
        return redirect(url_for('admin_fabricant'))
    finally:
        conn.close()

# Gestion des adresses MAC
@app.route('/manage_mac_addresses')
def manage_mac_addresses():
    if 'user_id' not in session or session['role'] != 'fabricant':
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    # Récupérer tous les clients
    clients = conn.execute('SELECT id, username FROM users WHERE role = "client"').fetchall()
    
    # Récupérer toutes les associations MAC
    locks = conn.execute('''
        SELECT l.id, l.mac_address, l.lock_name, u.username as client_username
        FROM locks l
        JOIN users u ON l.client_id = u.id
        ORDER BY u.username, l.lock_name
    ''').fetchall()
    
    conn.close()
    
    return render_template('manage_mac_addresses.html', clients=clients, locks=locks)

@app.route('/add_mac_address', methods=['POST'])
def add_mac_address():
    if 'user_id' not in session or session['role'] != 'fabricant':
        return redirect(url_for('login'))
        
    client_id = request.form['client_id']
    mac_address = request.form['mac_address'].upper()
    lock_name = request.form['lock_name']
    
    # Validation de l'adresse MAC
    import re
    if not re.match(r'^([0-9A-F]{2}[:-]){5}([0-9A-F]{2})$', mac_address):
        flash('Format d\'adresse MAC invalide. Utilisez le format AA:BB:CC:DD:EE:FF', 'error')
        return redirect(url_for('manage_mac_addresses'))
    
    conn = get_db_connection()
    
    # Vérifier si l'adresse MAC est déjà utilisée
    existing_mac = conn.execute('SELECT * FROM locks WHERE mac_address = ?', (mac_address,)).fetchone()
    if existing_mac:
        flash('Cette adresse MAC est déjà associée à un client.', 'error')
        conn.close()
        return redirect(url_for('manage_mac_addresses'))
    
    # Ajouter l'association
    conn.execute(
        'INSERT INTO locks (client_id, mac_address, lock_name) VALUES (?, ?, ?)',
        (client_id, mac_address, lock_name)
    )
    conn.commit()
    
    flash('Association de serrure ajoutée avec succès!', 'success')
    conn.close()
    return redirect(url_for('manage_mac_addresses'))

@app.route('/delete_mac_address/<int:lock_id>')
def delete_mac_address(lock_id):
    if 'user_id' not in session or session['role'] != 'fabricant':
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    conn.execute('DELETE FROM locks WHERE id = ?', (lock_id,))
    conn.commit()
    conn.close()
    
    flash('Association de serrure supprimée avec succès!', 'success')
    return redirect(url_for('manage_mac_addresses'))

if __name__ == '__main__':
    init_db()
    start_cleanup_thread()  # Démarrer le thread de nettoyage
    logger.info("Système de sécurité anti-bruteforce initialisé avec succès")
    logger.info(f"Limite de tentatives: {MAX_FAILED_ATTEMPTS}, durée de blocage: {LOCK_DURATION} secondes")
    app.run(debug=True, host='0.0.0.0')