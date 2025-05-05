from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3
from bcrypt import hashpw, gensalt, checkpw
import re
import datetime
import logging
from flask_cors import CORS
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)
app.secret_key = 'votre_clé_secrète'

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
            FOREIGN KEY (tag_id) REFERENCES tags (id),
            FOREIGN KEY (serrure_id) REFERENCES serrures (id)
        )
    ''')
    # Insertion d'un admin fabricant par défaut
    hashed_password = hashpw('password'.encode('utf-8'), gensalt()).decode('utf-8')
    execute_with_retry(conn, 'INSERT OR IGNORE INTO users (username, password, role, email) VALUES (?, ?, ?, ?)',
                   ('admin_fab', hashed_password, 'fabricant', 'admin@example.com'))
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
        execute_with_retry(conn, 'INSERT INTO actions (serrure_id, date_ouverture) VALUES (?, datetime("now"))', (serrure_id,))
        conn.commit()
        flash('Serrure ouverte avec succès.', 'success')
    else:
        flash('Code incorrect ou serrure non trouvée.', 'error')
    conn.close()
    return redirect(url_for('ouvrir_serrure', user_id=user_id))

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

    # Récupérer l'historique des actions
    actions = conn.execute('''
        SELECT actions.id, actions.date_ouverture, 
               tags.code_tag AS tag_code, 
               serrures.nom AS serrure_nom
        FROM actions
        LEFT JOIN tags ON actions.tag_id = tags.id
        LEFT JOIN serrures ON actions.serrure_id = serrures.id
        WHERE serrures.admin_client_id = ?
    ''', (user_id,)).fetchall()
    actions = [dict(action) for action in actions]

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
            # Mise à jour du code PIN
            new_code = request.form['code_ouverture']
            if not re.match(r'^\d{6}$', new_code):  # Vérifier le format du code PIN
                flash('Erreur : Le code PIN doit contenir exactement 6 chiffres.', 'error')
            else:
                try:
                    conn.execute('UPDATE serrures SET code_ouverture = ? WHERE id = ?', (new_code, item_id))
                    conn.commit()
                    flash('Code PIN modifié avec succès.', 'success')
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
@app.route('/verifier_acces', methods=['GET'])
def verifier_acces():
    logger.info("Requête reçue pour vérifier l'accès")
    card_id = request.args.get('card_id')
    code_pin = request.args.get('code_pin')
    logger.info(f"card_id: {card_id}, code_pin: {code_pin}")

    try:
        if not card_id and not code_pin:
            logger.error("No identifier provided in access verification request")
            return jsonify({
                "status": "BAD_REQUEST",
                "message": "Aucun identifiant fourni",
                "code": 400
            }), 400

        conn = get_db_connection()

        if card_id:
            # Validate card_id format
            if not re.match(r'^[0-9A-Fa-f]{4,}$', card_id):
                logger.warning(f"Invalid card_id format: {card_id}")
                return jsonify({
                    "status": "BAD_REQUEST",
                    "message": "Format de tag RFID invalide",
                    "code": 400
                }), 400

            tag = conn.execute('SELECT * FROM tags WHERE code_tag = ?', (card_id,)).fetchone()
            if not tag:
                logger.warning(f"Tag not found in database: {card_id}")
                return jsonify({
                    "status": "UNAUTHORIZED",
                    "message": "Tag non trouvé",
                    "code": 404
                }), 404

            # Convertir le jour actuel en français
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

            current_day = datetime.datetime.now().strftime('%A')  # Jour en anglais
            current_day_fr = convert_day_to_french(current_day).lower()  # Convertir en français et mettre en minuscule
            jours_autorises = [jour.strip().lower() for jour in tag['jours_autorises'].split(',')]  # Normaliser les jours autorisés

            # Logs pour déboguer
            logger.info(f"Jour actuel : {current_day_fr}")
            logger.info(f"Jours autorisés : {jours_autorises}")
            logger.info(f"Le jour {current_day_fr} est-il autorisé ? {current_day_fr in jours_autorises}")

            # Vérifier les conditions d'accès
            access_checks = [
                (tag['etat'] == 'autorisé', "Tag non autorisé"),
                (datetime.datetime.strptime(tag['date_debut'], '%Y-%m-%d').date() <= datetime.datetime.now().date() <= datetime.datetime.strptime(tag['date_fin'], '%Y-%m-%d').date(), "Hors période autorisée"),
                (current_day_fr in jours_autorises, "Jour non autorisé"),
                (datetime.datetime.strptime(tag['horaire_debut'], '%H:%M').time() <= datetime.datetime.now().time() <= datetime.datetime.strptime(tag['horaire_fin'], '%H:%M').time(), "Hors horaire autorisé")
            ]

            for condition, error_message in access_checks:
                if not condition:
                    logger.warning(f"Access denied for tag {card_id}: {error_message}")
                    return jsonify({
                        "status": "UNAUTHORIZED",
                        "message": error_message,
                        "code": 403
                    }), 403

            # Enregistrer l'action dans la base de données
            execute_with_retry(conn, 'INSERT INTO actions (tag_id, serrure_id, date_ouverture) VALUES (?, ?, datetime("now"))',
                               (tag['id'], tag['serrure_id']))
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
                return jsonify({

                    "status": "BAD_REQUEST",
                    "message": "Format de code PIN invalide",
                    "code": 400
                }), 400

            serrure = conn.execute('SELECT * FROM serrures WHERE code_ouverture = ?', (code_pin,)).fetchone()
            if serrure:
                # Enregistrer l'action dans la base de données
                execute_with_retry(conn, 'INSERT INTO actions (serrure_id, date_ouverture) VALUES (?, datetime("now"))',
                                   (serrure['id'],))
                conn.commit()
                logger.info(f"Access granted via PIN code")
                return jsonify({
                    "status": "AUTHORIZED",
                    "message": "Accès autorisé",
                    "code": 200
                }), 200
            else:
                logger.warning(f"Incorrect PIN code provided")
                return jsonify({
                    "status": "UNAUTHORIZED",
                    "message": "Code PIN incorrect",
                    "code": 403
                }), 403

    except Exception as e:
        logger.error(f"Error in access verification: {str(e)}")
        return jsonify({
            "status": "ERROR",
            "message": "Erreur interne du serveur",
            "code": 500
        }), 500
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/create_client')
def create_client():
    return render_template('create_client.html')

@app.route('/modify_client')
def modify_client():
    return render_template('modify_client.html')

@app.route('/list_clients')
def list_clients():
    conn = get_db_connection()
    clients = conn.execute('SELECT * FROM users WHERE role = ?', ('client',)).fetchall()
    conn.close()
    return render_template('list_clients.html', clients=clients)

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
                INSERT INTO tags (nom_proprietaire, code_tag, serrure_id)
                VALUES (?, ?, ?)
            ''', (serrure_name, code_rfid, serrure['id']))
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

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0')