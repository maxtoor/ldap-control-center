# Installazione Completa su Debian (senza Docker)

Questa guida descrive una installazione completa su Debian con:

- OpenLDAP
- LDAP Control Center (FastAPI/Uvicorn)
- phpLDAPadmin
- Nginx + PHP-FPM
- TLS con Let's Encrypt

## 1. Prerequisiti

- Debian 12 (o compatibile)
- DNS configurato per:
  - `ldapcc.tuodominio.it` (app)
  - `ldapadmin.tuodominio.it` (phpLDAPadmin)
- Accesso `sudo`
- Porte aperte: `80`, `443`, `22`

## 2. Installazione pacchetti

```bash
sudo apt update
sudo apt install -y \
  git curl ca-certificates unzip \
  python3 python3-venv python3-pip \
  nginx certbot python3-certbot-nginx \
  slapd ldap-utils \
  php-fpm php-ldap
```

## 3. Configurazione OpenLDAP

Se necessario riconfigura slapd:

```bash
sudo dpkg-reconfigure slapd
```

Parametri consigliati:

- Domain: `example.org` (o il tuo dominio)
- Base DN risultante: `dc=example,dc=org`
- Admin DN: `cn=admin,dc=example,dc=org`
- Password admin LDAP: robusta

Test autenticazione LDAP:

```bash
ldapwhoami -x -H ldap://127.0.0.1 -D "cn=admin,dc=example,dc=org" -W
```

## 4. Installazione LDAP Control Center

```bash
sudo useradd --system --create-home --home /opt/ldap-control-center --shell /usr/sbin/nologin ldapcc
sudo mkdir -p /opt/ldap-control-center
sudo chown -R ldapcc:ldapcc /opt/ldap-control-center

cd /opt/ldap-control-center
sudo -u ldapcc git clone https://github.com/maxtoor/ldap-control-center.git .
sudo -u ldapcc python3 -m venv .venv
sudo -u ldapcc .venv/bin/pip install --upgrade pip
sudo -u ldapcc .venv/bin/pip install -r requirements.txt
```

## 5. Configurazione `.env`

```bash
sudo -u ldapcc cp /opt/ldap-control-center/.env.example /opt/ldap-control-center/.env
sudo -u ldapcc nano /opt/ldap-control-center/.env
```

Valori minimi da aggiornare:

```env
LDAP_HOST=127.0.0.1
LDAP_PORT=389
LDAP_USE_SSL=false
LDAP_ADMIN_DN=cn=admin,dc=example,dc=org
LDAP_ADMIN_PASSWORD=PASSWORD_LDAP_ADMIN
LDAP_USERS_BASE_DN=ou=users,dc=example,dc=org
LDAP_GROUPS_BASE_DN=ou=groups,dc=example,dc=org

APP_ADMIN_USERNAME=admin
APP_ADMIN_PASSWORD=PASSWORD_APP_ADMIN
APP_SESSION_SECRET=STRINGA_RANDOM_LUNGA

PASSWORD_RESET_BASE_URL=https://ldapcc.tuodominio.it
PASSWORD_RESET_SHOW_LINK=false
```

Nota: all'avvio l'app prova a creare automaticamente le OU `users` e `groups` se non esistono.

## 6. Servizio systemd per l'app

Crea unit file:

```bash
sudo tee /etc/systemd/system/ldapcc.service >/dev/null <<'EOF_SERVICE'
[Unit]
Description=LDAP Control Center (FastAPI)
After=network.target

[Service]
User=ldapcc
Group=ldapcc
WorkingDirectory=/opt/ldap-control-center
EnvironmentFile=/opt/ldap-control-center/.env
ExecStart=/opt/ldap-control-center/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF_SERVICE
```

Abilita il servizio:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ldapcc
sudo systemctl status ldapcc
```

## 7. Installazione e configurazione phpLDAPadmin

Installa pacchetto:

```bash
sudo apt install -y phpldapadmin
```

Configura host e base DN in:

```bash
sudo nano /etc/phpldapadmin/config.php
```

Impostazioni essenziali:

- host LDAP: `127.0.0.1`
- base DN: `dc=example,dc=org`

## 8. Configurazione Nginx

### 8.1 LDAP Control Center (reverse proxy)

```bash
sudo tee /etc/nginx/sites-available/ldapcc >/dev/null <<'EOF'
server {
    listen 80;
    server_name ldapcc.tuodominio.it;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF
```

### 8.2 phpLDAPadmin con PHP-FPM

```bash
sudo tee /etc/nginx/sites-available/phpldapadmin >/dev/null <<'EOF'
server {
    listen 80;
    server_name ldapadmin.tuodominio.it;

    root /usr/share/phpldapadmin/htdocs;
    index index.php;

    location / {
        try_files $uri $uri/ /index.php?$args;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php8.2-fpm.sock;
    }

    location ~ /\.ht {
        deny all;
    }
}
EOF
```

Abilita siti e servizi:

```bash
sudo ln -s /etc/nginx/sites-available/ldapcc /etc/nginx/sites-enabled/ldapcc
sudo ln -s /etc/nginx/sites-available/phpldapadmin /etc/nginx/sites-enabled/phpldapadmin

sudo nginx -t
sudo systemctl enable --now nginx
sudo systemctl enable --now php8.2-fpm
sudo systemctl reload nginx
```

## 9. TLS con Let's Encrypt

```bash
sudo certbot --nginx -d ldapcc.tuodominio.it -d ldapadmin.tuodominio.it
```

Test rinnovo:

```bash
sudo certbot renew --dry-run
```

## 10. Hardening consigliato

- Cambiare subito password default (`APP_ADMIN_*`, `LDAP_ADMIN_PASSWORD`)
- Limitare accesso a phpLDAPadmin per IP o Basic Auth
- Tenere `PASSWORD_RESET_SHOW_LINK=false` in produzione
- Impostare SMTP reale per reset password via email

Esempio restrizione IP per phpLDAPadmin (in server block):

```nginx
location / {
    allow 1.2.3.4;
    deny all;
    try_files $uri $uri/ /index.php?$args;
}
```

## 11. Verifica finale

```bash
systemctl status slapd
systemctl status ldapcc
systemctl status nginx
systemctl status php8.2-fpm

curl -I http://127.0.0.1:8000
curl -I https://ldapcc.tuodominio.it
curl -I https://ldapadmin.tuodominio.it
```

## 12. Aggiornamento applicazione

```bash
cd /opt/ldap-control-center
sudo -u ldapcc git pull
sudo -u ldapcc .venv/bin/pip install -r requirements.txt
sudo systemctl restart ldapcc
```
