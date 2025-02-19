# Projet Darkly - Exploitation des failles de sécurité

## Introduction
Le projet **Darkly** est une étude de cas sur les vulnérabilités courantes des applications web. Il met en avant différentes failles de sécurité qui peuvent compromettre un site web et propose des moyens pour les comprendre, les exploiter et surtout les corriger.

Ce document détaille chaque faille abordée dans le projet et propose des solutions pour les éviter.

---

## 1. Injection SQL basique
### Explication de la faille
L'injection SQL est une technique qui permet d'interagir avec la base de données en manipulant une requête SQL via un champ utilisateur. Un attaquant peut injecter des commandes SQL malveillantes pour récupérer, modifier ou supprimer des données sensibles.

### Exploitation
Exemple d'injection basique :
```
1' OR '1'='1
```
Ceci force la requête à toujours être vraie, permettant d'accéder à des informations protégées.

### Correction
- Utilisation de **requêtes préparées** et de **paramètres liés**.
- Filtrage des entrées utilisateurs.

---

## 2. Injection SQL avancée
### Explication
Une injection SQL avancée permet d'exécuter des commandes SQL complexes, comme énumérer les bases de données ou extraire des informations sensibles.

### Exploitation
Utilisation de `UNION SELECT` pour récupérer des données d’autres tables :
```
1 UNION SELECT username, password FROM users;
```

### Correction
- Appliquer des **politiques de moindre privilège**.
- Vérifier les permissions des utilisateurs.

---

## 3. Inclusion de fichiers (LFI & RFI)
### Explication
L’inclusion de fichiers permet à un attaquant de lire ou d'exécuter des fichiers distants ou locaux via des paramètres d'URL mal sécurisés.

### Exploitation
```
?page=../../../../etc/passwd
```

### Correction
- Désactiver `allow_url_include` en PHP.
- Vérifier et filtrer les entrées utilisateur.
- Restreindre les accès aux fichiers sensibles.

---

## 4. Cross-Site Scripting (XSS)
### Explication
Le XSS permet d'injecter du code JavaScript malveillant dans une page web.

### Exploitation
```
<script>alert('XSS');</script>
```

### Correction
- Échapper les caractères spéciaux (`<`, `>`, `"`, `'`).
- Utiliser `Content Security Policy (CSP)`.

---

## 5. Cookies non sécurisés
### Explication
Un attaquant peut intercepter ou manipuler un cookie pour usurper l’identité d’un utilisateur.

### Correction
- Utiliser `Secure` et `HttpOnly` sur les cookies.
- Implémenter des tokens CSRF pour la validation des actions utilisateur.

---

## 6. Spoofing via cURL
### Explication
Un attaquant peut modifier les en-têtes HTTP pour manipuler les requêtes envoyées au serveur.

### Correction
- Vérifier l’origine des requêtes.
- Mettre en place des tokens d’authentification.

---

## 7. Exploitation de `.htpasswd`
### Explication
L’exposition d’un fichier `.htpasswd` contenant des mots de passe hachés permet à un attaquant d’en récupérer le contenu.

### Correction
- Ne jamais exposer de fichiers sensibles sur un serveur public.
- Utiliser un `.htaccess` pour bloquer l’accès aux fichiers.

---

## 8. Brute Force sur la connexion
### Explication
Une page de connexion sans protection permet de tester des milliers de mots de passe.

### Correction
- Mettre en place un **captcha**.
- Limiter le nombre de tentatives par IP.
- Exiger des mots de passe complexes.

---

## 9. Upload de fichiers malveillants
### Explication
Si l’upload d’un fichier n’est pas sécurisé, un attaquant peut téléverser un fichier exécutable sur le serveur.

### Correction
- Restreindre les types de fichiers acceptés.
- Stocker les fichiers téléversés en dehors du répertoire public.

---

## 10. Redirections non sécurisées
### Explication
Une redirection ouverte peut être exploitée pour du phishing.

### Correction
- Vérifier les URLs de redirection.
- Implémenter une liste blanche d’URLs autorisées.

---

## 11. Recherche de fichiers cachés
### Explication
L’analyse des fichiers `robots.txt` peut révéler des chemins sensibles.

### Correction
- Ne pas inclure de fichiers sensibles dans `robots.txt`.
- Protéger l’accès aux répertoires importants.

---

## 12. Failles liées aux surveys et aux récupérations d’informations
### Explication
Les formulaires de feedback ou de récupération d’informations peuvent être utilisés pour extraire des données confidentielles.

### Correction
- Mettre en place une validation côté serveur.
- Empêcher l'affichage des erreurs SQL.

---

## Conclusion
Le projet **Darkly** met en avant de nombreuses failles de sécurité et propose différentes méthodes d'exploitation. Ce document a permis d’expliquer chaque vulnérabilité rencontrée et les bonnes pratiques à suivre pour les éviter. La sécurité applicative repose sur une combinaison de bonnes pratiques de développement, d'une validation stricte des entrées et de mécanismes de protection adéquats.

---

## Références
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Security Headers](https://securityheaders.com/)
- [NIST Guidelines](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63b.pdf)