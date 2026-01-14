#!/bin/bash

# ===================================================================
# Script d'audit de sécurité mail - VERSION HTML MODERNE
# Auteur : Communauté YunoHost
# Licence : MIT
# Repository : https://github.com/gamersalpha/yunohost-mail-security-audit
# Description : Génère un rapport HTML de sécurité mail sur une période configurable
# ===================================================================

LOG_FILE="/var/log/mail.log"
AUTH_LOG="/var/log/auth.log"
HTML_FILE="/tmp/mail_security_report_$(date +%Y%m%d_%H%M%S).html"

# ⚠️ CONFIGURATION - MODIFIEZ CES LIGNES ⚠️
ALERT_EMAIL="votre-email@domaine.fr"
ANALYSIS_PERIOD=7  # Nombre de jours à analyser (1=aujourd'hui, 7=semaine, 30=mois)

# Collecte des données
END_DATE=$(date '+%Y-%m-%d')
START_DATE=$(date -d "$ANALYSIS_PERIOD days ago" '+%Y-%m-%d')
PERIOD_DISPLAY="du $START_DATE au $END_DATE ($ANALYSIS_PERIOD jours)"
HOSTNAME=$(hostname -f)
PUBLIC_IP=$(curl -s ifconfig.me 2>/dev/null || echo "N/A")
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# Statistiques sur la période définie (avec tous les logs)
TOTAL_ATTEMPTS=$(cat /var/log/mail.log /var/log/mail.log.1 2>/dev/null | \
    awk -v start="$START_DATE" -v end="$END_DATE" '$0 >= start && $0 <= end' | \
    grep "auth=0/1" | wc -l)

EXTERNAL_AUTH=$(cat /var/log/mail.log /var/log/mail.log.1 2>/dev/null | \
    awk -v start="$START_DATE" -v end="$END_DATE" '$0 >= start && $0 <= end' | \
    grep "sasl_method=" | \
    grep -vE "192.168|10\.|172\.(1[6-9]|2[0-9]|3[01])|127\.0\.0\.1" | wc -l)

SENT_MAILS=$(cat /var/log/mail.log /var/log/mail.log.1 2>/dev/null | \
    awk -v start="$START_DATE" -v end="$END_DATE" '$0 >= start && $0 <= end' | \
    grep "status=sent" | wc -l)

BANNED_TOTAL=0

if systemctl is-active --quiet fail2ban; then
    FAIL2BAN_STATUS="✓ Actif"
    FAIL2BAN_COLOR="#10b981"
    for jail in postfix sasl dovecot sshd; do
        if fail2ban-client status "$jail" &>/dev/null; then
            BANNED=$(fail2ban-client status "$jail" 2>/dev/null | grep "Currently banned" | awk '{print $4}')
            BANNED_TOTAL=$((BANNED_TOTAL + BANNED))
        fi
    done
else
    FAIL2BAN_STATUS="✗ Inactif"
    FAIL2BAN_COLOR="#ef4444"
fi

# Déterminer le statut global
if [ "$EXTERNAL_AUTH" -eq 0 ] && [ "$SENT_MAILS" -lt 200 ] && [ "$TOTAL_ATTEMPTS" -lt 100 ]; then
    GLOBAL_STATUS="SÉCURISÉ"
    GLOBAL_COLOR="#10b981"
    GLOBAL_ICON="✓"
    SUBJECT="[OK] Rapport Sécurité Mail ($ANALYSIS_PERIOD jours) - $HOSTNAME - $(date +%d/%m/%Y)"
else
    GLOBAL_STATUS="ATTENTION"
    GLOBAL_COLOR="#f59e0b"
    GLOBAL_ICON="⚠"
    SUBJECT="[ALERTE] Rapport Sécurité Mail ($ANALYSIS_PERIOD jours) - $HOSTNAME - $(date +%d/%m/%Y)"
fi

# Top 5 IPs attaquantes sur la période
TOP_IPS=$(cat /var/log/mail.log /var/log/mail.log.1 2>/dev/null | \
    awk -v start="$START_DATE" -v end="$END_DATE" '$0 >= start && $0 <= end' | \
    grep "auth=0" | \
    grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | \
    sort | uniq -c | sort -rn | head -5)

# Top utilisateurs légitimes sur la période
TOP_USERS=$(cat /var/log/mail.log /var/log/mail.log.1 2>/dev/null | \
    awk -v start="$START_DATE" -v end="$END_DATE" '$0 >= start && $0 <= end' | \
    grep "sasl_username=" | \
    grep -oE "sasl_username=[^,]+" | \
    awk -F= '{print $2}' | \
    sort | uniq -c | sort -rn | head -5)

# Top 5 expéditeurs sur la période (CORRIGÉ - cherche dans qmgr)
TOP_SENDERS=$(cat /var/log/mail.log /var/log/mail.log.1 2>/dev/null | \
    awk -v start="$START_DATE" -v end="$END_DATE" '$0 >= start && $0 <= end' | \
    grep "postfix/qmgr" | \
    grep -oE "from=<[^>]+>" | \
    sed 's/from=<//g' | sed 's/>//g' | \
    sort | uniq -c | sort -rn | head -5)

# Si TOP_SENDERS est vide, essayer sans les < >
if [ -z "$TOP_SENDERS" ]; then
    TOP_SENDERS=$(cat /var/log/mail.log /var/log/mail.log.1 2>/dev/null | \
        awk -v start="$START_DATE" -v end="$END_DATE" '$0 >= start && $0 <= end' | \
        grep "postfix/qmgr" | \
        grep -oE "from=[^,]+" | \
        sed 's/from=//g' | sed 's/<//g' | sed 's/>//g' | \
        sort | uniq -c | sort -rn | head -5)
fi

# Top 5 destinataires sur la période
TOP_RECIPIENTS=$(cat /var/log/mail.log /var/log/mail.log.1 2>/dev/null | \
    awk -v start="$START_DATE" -v end="$END_DATE" '$0 >= start && $0 <= end' | \
    grep "status=sent" | \
    grep -oE "to=<[^>]+>" | \
    sed 's/to=<//g' | sed 's/>//g' | \
    sort | uniq -c | sort -rn | head -5)

# Si TOP_RECIPIENTS est vide, essayer sans les < >
if [ -z "$TOP_RECIPIENTS" ]; then
    TOP_RECIPIENTS=$(cat /var/log/mail.log /var/log/mail.log.1 2>/dev/null | \
        awk -v start="$START_DATE" -v end="$END_DATE" '$0 >= start && $0 <= end' | \
        grep "status=sent" | \
        grep -oE "to=[^,]+" | \
        sed 's/to=//g' | sed 's/<//g' | sed 's/>//g' | \
        sort | uniq -c | sort -rn | head -5)
fi

# Génération du HTML
cat > "$HTML_FILE" << 'HTMLEOF'
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport de Sécurité Mail</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; color: #1f2937; }
        .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 20px; box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3); overflow: hidden; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; text-align: center; }
        .header h1 { font-size: 32px; font-weight: 700; margin-bottom: 10px; }
        .header p { font-size: 16px; opacity: 0.9; }
        .status-banner { padding: 30px 40px; background: GLOBAL_COLOR_PLACEHOLDER; color: white; text-align: center; font-size: 24px; font-weight: 700; letter-spacing: 1px; }
        .content { padding: 40px; }
        .info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 40px; }
        .info-card { background: #f9fafb; border-radius: 12px; padding: 20px; border-left: 4px solid #667eea; }
        .info-card h3 { font-size: 14px; color: #6b7280; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px; }
        .info-card p { font-size: 18px; font-weight: 600; color: #1f2937; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 40px; }
        .stat-card { background: white; border: 2px solid #e5e7eb; border-radius: 12px; padding: 24px; text-align: center; transition: all 0.3s ease; }
        .stat-card:hover { transform: translateY(-5px); box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1); }
        .stat-number { font-size: 48px; font-weight: 700; margin-bottom: 8px; }
        .stat-label { font-size: 14px; color: #6b7280; text-transform: uppercase; letter-spacing: 0.5px; }
        .stat-card.danger .stat-number { color: #ef4444; }
        .stat-card.warning .stat-number { color: #f59e0b; }
        .stat-card.success .stat-number { color: #10b981; }
        .stat-card.info .stat-number { color: #3b82f6; }
        .section { margin-bottom: 40px; }
        .section-title { font-size: 24px; font-weight: 700; margin-bottom: 20px; color: #1f2937; padding-bottom: 10px; border-bottom: 3px solid #667eea; }
        .table-container { background: white; border-radius: 12px; overflow: hidden; border: 1px solid #e5e7eb; }
        table { width: 100%; border-collapse: collapse; }
        thead { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; }
        th { padding: 16px; text-align: left; font-weight: 600; text-transform: uppercase; font-size: 12px; letter-spacing: 0.5px; }
        td { padding: 16px; border-bottom: 1px solid #e5e7eb; }
        tr:last-child td { border-bottom: none; }
        tbody tr:hover { background: #f9fafb; }
        .badge { display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; text-transform: uppercase; }
        .badge-danger { background: #fee2e2; color: #dc2626; }
        .badge-success { background: #d1fae5; color: #059669; }
        .badge-warning { background: #fef3c7; color: #d97706; }
        .badge-info { background: #dbeafe; color: #1d4ed8; }
        .alert { padding: 16px; border-radius: 12px; margin-bottom: 20px; border-left: 4px solid; }
        .alert-success { background: #d1fae5; border-color: #059669; color: #065f46; }
        .alert-warning { background: #fef3c7; border-color: #d97706; color: #92400e; }
        .alert-danger { background: #fee2e2; border-color: #dc2626; color: #991b1b; }
        .footer { background: #f9fafb; padding: 30px 40px; text-align: center; color: #6b7280; font-size: 14px; border-top: 1px solid #e5e7eb; }
        .footer strong { color: #1f2937; }
        @media (max-width: 768px) { .stats-grid, .info-grid { grid-template-columns: 1fr; } table { font-size: 14px; } th, td { padding: 12px 8px; } }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Rapport de Sécurité Mail</h1>
            <p>Serveur HOSTNAME_PLACEHOLDER - Période : PERIOD_PLACEHOLDER</p>
        </div>
        <div class="status-banner">GLOBAL_ICON_PLACEHOLDER STATUT : GLOBAL_STATUS_PLACEHOLDER</div>
        <div class="content">
            <div class="info-grid">
                <div class="info-card"><h3>Serveur</h3><p>HOSTNAME_PLACEHOLDER</p></div>
                <div class="info-card"><h3>IP Publique</h3><p>PUBLIC_IP_PLACEHOLDER</p></div>
                <div class="info-card"><h3>Date du rapport</h3><p>TIMESTAMP_PLACEHOLDER</p></div>
                <div class="info-card"><h3>Fail2ban</h3><p>FAIL2BAN_STATUS_PLACEHOLDER</p></div>
            </div>
            <div class="stats-grid">
                <div class="stat-card danger"><div class="stat-number">TOTAL_ATTEMPTS_PLACEHOLDER</div><div class="stat-label">Tentatives d'attaque</div></div>
                <div class="stat-card warning"><div class="stat-number">BANNED_TOTAL_PLACEHOLDER</div><div class="stat-label">IPs bannies</div></div>
                <div class="stat-card info"><div class="stat-number">SENT_MAILS_PLACEHOLDER</div><div class="stat-label">Mails envoyés</div></div>
                <div class="stat-card success"><div class="stat-number">EXTERNAL_AUTH_PLACEHOLDER</div><div class="stat-label">Connexions externes</div></div>
            </div>
            <div class="section"><h2 class="section-title">🔔 Alertes de Sécurité</h2>ALERTS_PLACEHOLDER</div>
            <div class="section"><h2 class="section-title">🎯 Top 5 des IPs Attaquantes</h2><div class="table-container"><table><thead><tr><th>Adresse IP</th><th>Tentatives</th><th>Statut</th></tr></thead><tbody>TOP_IPS_PLACEHOLDER</tbody></table></div></div>
            <div class="section"><h2 class="section-title">👥 Connexions Légitimes</h2><div class="table-container"><table><thead><tr><th>Utilisateur</th><th>Connexions</th><th>Type</th></tr></thead><tbody>TOP_USERS_PLACEHOLDER</tbody></table></div></div>
            <div class="section"><h2 class="section-title">📧 Top 5 des Expéditeurs</h2><div class="table-container"><table><thead><tr><th>Expéditeur</th><th>Mails envoyés</th><th>Type</th></tr></thead><tbody>TOP_SENDERS_PLACEHOLDER</tbody></table></div></div>
            <div class="section"><h2 class="section-title">📬 Top 5 des Destinataires</h2><div class="table-container"><table><thead><tr><th>Destinataire</th><th>Mails reçus</th><th>Type</th></tr></thead><tbody>TOP_RECIPIENTS_PLACEHOLDER</tbody></table></div></div>
            <div class="section"><h2 class="section-title">🚫 IPs Actuellement Bannies</h2><div class="table-container"><table><thead><tr><th>Jail</th><th>IPs Bannies</th></tr></thead><tbody>BANNED_IPS_PLACEHOLDER</tbody></table></div></div>
        </div>
        <div class="footer"><p>Rapport généré automatiquement par <strong>Mail Security Audit</strong></p><p>Serveur YunoHost • Fail2ban • Postfix • Dovecot</p></div>
    </div>
</body>
</html>
HTMLEOF

# Remplacement des placeholders
sed -i "s|HOSTNAME_PLACEHOLDER|$HOSTNAME|g" "$HTML_FILE"
sed -i "s|PUBLIC_IP_PLACEHOLDER|$PUBLIC_IP|g" "$HTML_FILE"
sed -i "s|TIMESTAMP_PLACEHOLDER|$TIMESTAMP|g" "$HTML_FILE"
sed -i "s|PERIOD_PLACEHOLDER|$PERIOD_DISPLAY|g" "$HTML_FILE"
sed -i "s|TOTAL_ATTEMPTS_PLACEHOLDER|$TOTAL_ATTEMPTS|g" "$HTML_FILE"
sed -i "s|EXTERNAL_AUTH_PLACEHOLDER|$EXTERNAL_AUTH|g" "$HTML_FILE"
sed -i "s|SENT_MAILS_PLACEHOLDER|$SENT_MAILS|g" "$HTML_FILE"
sed -i "s|BANNED_TOTAL_PLACEHOLDER|$BANNED_TOTAL|g" "$HTML_FILE"
sed -i "s|FAIL2BAN_STATUS_PLACEHOLDER|$FAIL2BAN_STATUS|g" "$HTML_FILE"
sed -i "s|GLOBAL_STATUS_PLACEHOLDER|$GLOBAL_STATUS|g" "$HTML_FILE"
sed -i "s|GLOBAL_ICON_PLACEHOLDER|$GLOBAL_ICON|g" "$HTML_FILE"
sed -i "s|GLOBAL_COLOR_PLACEHOLDER|$GLOBAL_COLOR|g" "$HTML_FILE"

# Génération des alertes
ALERTS_HTML=""
if [ "$EXTERNAL_AUTH" -eq 0 ] && [ "$SENT_MAILS" -lt 200 ] && [ "$TOTAL_ATTEMPTS" -lt 100 ]; then
    ALERTS_HTML='<div class="alert alert-success"><strong>✓ Tout est OK !</strong> Aucune anomalie détectée sur la période analysée. Le serveur fonctionne normalement.</div>'
else
    if [ "$EXTERNAL_AUTH" -gt 0 ]; then
        ALERTS_HTML+='<div class="alert alert-warning"><strong>⚠ Authentifications externes détectées</strong> : '$EXTERNAL_AUTH' connexions depuis l extérieur du réseau local sur les '$ANALYSIS_PERIOD' derniers jours.</div>'
    fi
    if [ "$TOTAL_ATTEMPTS" -gt 100 ]; then
        ALERTS_HTML+='<div class="alert alert-danger"><strong>✗ Volume d attaques élevé</strong> : '$TOTAL_ATTEMPTS' tentatives d authentification échouées sur les '$ANALYSIS_PERIOD' derniers jours.</div>'
    fi
    if [ "$SENT_MAILS" -gt 200 ]; then
        ALERTS_HTML+='<div class="alert alert-warning"><strong>⚠ Volume de mails élevé</strong> : '$SENT_MAILS' mails envoyés sur les '$ANALYSIS_PERIOD' derniers jours. Vérifier si spam.</div>'
    fi
fi
sed -i "s|ALERTS_PLACEHOLDER|$ALERTS_HTML|g" "$HTML_FILE"

# Génération du tableau des IPs
TOP_IPS_HTML=""
while IFS= read -r line; do
    if [ -n "$line" ]; then
        COUNT=$(echo "$line" | awk '{print $1}')
        IP=$(echo "$line" | awk '{print $2}')
        if [ "$COUNT" -gt 100 ]; then
            BADGE='<span class="badge badge-danger">Critique</span>'
        elif [ "$COUNT" -gt 50 ]; then
            BADGE='<span class="badge badge-warning">Élevé</span>'
        else
            BADGE='<span class="badge badge-success">Normal</span>'
        fi
        TOP_IPS_HTML+="<tr><td><strong>$IP</strong></td><td>$COUNT</td><td>$BADGE</td></tr>"
    fi
done <<< "$TOP_IPS"
[ -z "$TOP_IPS_HTML" ] && TOP_IPS_HTML='<tr><td colspan="3" style="text-align:center; color: #10b981;">Aucune attaque détectée sur la période ✓</td></tr>'
sed -i "s|TOP_IPS_PLACEHOLDER|$TOP_IPS_HTML|g" "$HTML_FILE"

# Génération du tableau des utilisateurs
TOP_USERS_HTML=""
while IFS= read -r line; do
    if [ -n "$line" ]; then
        COUNT=$(echo "$line" | awk '{print $1}')
        USER=$(echo "$line" | awk '{print $2}')
        TOP_USERS_HTML+="<tr><td><strong>$USER</strong></td><td>$COUNT</td><td><span class=\"badge badge-success\">Légitime</span></td></tr>"
    fi
done <<< "$TOP_USERS"
[ -z "$TOP_USERS_HTML" ] && TOP_USERS_HTML='<tr><td colspan="3" style="text-align:center;">Aucune connexion sur la période</td></tr>'
sed -i "s|TOP_USERS_PLACEHOLDER|$TOP_USERS_HTML|g" "$HTML_FILE"

# Génération du tableau des expéditeurs
TOP_SENDERS_HTML=""
while IFS= read -r line; do
    if [ -n "$line" ]; then
        COUNT=$(echo "$line" | awk '{print $1}')
        SENDER=$(echo "$line" | awk '{$1=""; print $0}' | sed 's/^ //')
        if [[ "$SENDER" == *"nextcloud"* ]] || [[ "$SENDER" == *"backup"* ]] || [[ "$SENDER" == *"root"* ]] || [[ "$SENDER" == *"diagnosis"* ]] || [[ "$SENDER" == *"qnap"* ]] || [[ "$SENDER" == *"vaultwarden"* ]]; then
            TYPE='<span class="badge badge-info">Système</span>'
        else
            TYPE='<span class="badge badge-success">Utilisateur</span>'
        fi
        TOP_SENDERS_HTML+="<tr><td><strong>$SENDER</strong></td><td>$COUNT</td><td>$TYPE</td></tr>"
    fi
done <<< "$TOP_SENDERS"
[ -z "$TOP_SENDERS_HTML" ] && TOP_SENDERS_HTML='<tr><td colspan="3" style="text-align:center;">Aucun mail envoyé sur la période</td></tr>'
sed -i "s|TOP_SENDERS_PLACEHOLDER|$TOP_SENDERS_HTML|g" "$HTML_FILE"

# Génération du tableau des destinataires
TOP_RECIPIENTS_HTML=""
while IFS= read -r line; do
    if [ -n "$line" ]; then
        COUNT=$(echo "$line" | awk '{print $1}')
        RECIPIENT=$(echo "$line" | awk '{$1=""; print $0}' | sed 's/^ //')
        DOMAIN=$(echo "$HOSTNAME" | cut -d. -f2-)
        if [[ "$RECIPIENT" == *"@$DOMAIN"* ]] || [[ "$RECIPIENT" == *"@$HOSTNAME"* ]] || [[ "$RECIPIENT" == "root" ]]; then
            TYPE='<span class="badge badge-info">Interne</span>'
        else
            TYPE='<span class="badge badge-success">Externe</span>'
        fi
        TOP_RECIPIENTS_HTML+="<tr><td><strong>$RECIPIENT</strong></td><td>$COUNT</td><td>$TYPE</td></tr>"
    fi
done <<< "$TOP_RECIPIENTS"
[ -z "$TOP_RECIPIENTS_HTML" ] && TOP_RECIPIENTS_HTML='<tr><td colspan="3" style="text-align:center;">Aucun destinataire sur la période</td></tr>'
sed -i "s|TOP_RECIPIENTS_PLACEHOLDER|$TOP_RECIPIENTS_HTML|g" "$HTML_FILE"

# Génération du tableau des IPs bannies
BANNED_IPS_HTML=""
for jail in postfix sasl dovecot sshd; do
    if fail2ban-client status "$jail" &>/dev/null; then
        BANNED_LIST=$(fail2ban-client status "$jail" 2>/dev/null | grep "Banned IP list" | awk -F: '{print $2}' | xargs)
        if [ -n "$BANNED_LIST" ] && [ "$BANNED_LIST" != " " ]; then
            BANNED_IPS_HTML+="<tr><td><strong>$jail</strong></td><td>$BANNED_LIST</td></tr>"
        fi
    fi
done
[ -z "$BANNED_IPS_HTML" ] && BANNED_IPS_HTML='<tr><td colspan="2" style="text-align:center; color: #10b981;">Aucune IP bannie actuellement ✓</td></tr>'
sed -i "s|BANNED_IPS_PLACEHOLDER|$BANNED_IPS_HTML|g" "$HTML_FILE"

# Envoi par email
if [ -n "$ALERT_EMAIL" ]; then
    if command -v mutt &> /dev/null; then
        mutt -e "set content_type=text/html" -s "$SUBJECT" "$ALERT_EMAIL" < "$HTML_FILE"
        echo "$(date '+%Y-%m-%d %H:%M:%S') - Rapport HTML envoyé à $ALERT_EMAIL (période: $ANALYSIS_PERIOD jours)" >> /var/log/mail_audit.log
    else
        echo "$(date '+%Y-%m-%d %H:%M:%S') - ERREUR : mutt non installé" >> /var/log/mail_audit.log
        echo "ERREUR : mutt n'est pas installé. Installez-le avec : sudo apt install mutt -y"
    fi
else
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ERREUR : Email destinataire non configuré" >> /var/log/mail_audit.log
    echo "ERREUR : Veuillez configurer ALERT_EMAIL dans le script (ligne 16)"
fi

# Nettoyage automatique (garde 30 jours)
find /tmp -name "mail_security_report_*.html" -mtime +30 -delete 2>/dev/null

exit 0
