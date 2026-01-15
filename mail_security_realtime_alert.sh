#!/bin/bash

# ===================================================================
# Script d'alerte temps réel - Sécurité Mail
# Auteur : Communauté YunoHost
# Licence : MIT
# Repository : https://github.com/gamersalpha/yunohost-mail-security-audit
# Description : Envoie une alerte immédiate en cas d'attaque massive
# Version : 1.3.1 - Avec géolocalisation et HTML
# ===================================================================

# ⚠️ CONFIGURATION - MODIFIEZ CES LIGNES ⚠️
ALERT_EMAIL="votre-email@domaine.fr"
THRESHOLD_ATTEMPTS=50  # Nombre de tentatives qui déclenchent une alerte
TIME_WINDOW=60         # Fenêtre de temps en minutes

LOG_FILE="/var/log/mail.log"
LOCK_FILE="/tmp/mail_alert.lock"
COOLDOWN_FILE="/tmp/mail_alert_cooldown"
COOLDOWN_MINUTES=60    # Éviter le spam d'alertes (1 alerte par heure max)
HTML_FILE="/tmp/mail_alert_$(date +%Y%m%d_%H%M%S).html"

# Fonction de géolocalisation IP (identique au script principal)
get_country() {
    local ip=$1
    if command -v geoiplookup &> /dev/null; then
        geoip_result=$(geoiplookup "$ip" 2>/dev/null)
        country_code=$(echo "$geoip_result" | awk -F': ' '{print $2}' | awk -F',' '{print $1}' | xargs)
        
        if [[ -z "$country_code" || "$country_code" == "IP Address not found" ]]; then
            echo "🌍 Inconnu"
            return
        fi
        
        case "$country_code" in
            "NL") echo "🌐 Pays-Bas" ;;
            "DE") echo "🌐 Allemagne" ;;
            "FR") echo "🌐 France" ;;
            "GB") echo "🌐 Royaume-Uni" ;;
            "IT") echo "🌐 Italie" ;;
            "ES") echo "🌐 Espagne" ;;
            "BG") echo "🌐 Bulgarie" ;;
            "RO") echo "🌐 Roumanie" ;;
            "PL") echo "🌐 Pologne" ;;
            "US") echo "🌐 États-Unis" ;;
            "CA") echo "🌐 Canada" ;;
            "CN") echo "🌐 Chine" ;;
            "RU") echo "🌐 Russie" ;;
            "IN") echo "🌐 Inde" ;;
            "JP") echo "🌐 Japon" ;;
            "BR") echo "🌐 Brésil" ;;
            "TR") echo "🌐 Turquie" ;;
            *) echo "🌍 $country_code" ;;
        esac
    else
        echo "❓ N/A"
    fi
}

# Vérifier le cooldown (éviter trop d'alertes)
if [ -f "$COOLDOWN_FILE" ]; then
    LAST_ALERT=$(cat "$COOLDOWN_FILE")
    CURRENT_TIME=$(date +%s)
    TIME_DIFF=$(( (CURRENT_TIME - LAST_ALERT) / 60 ))
    
    if [ "$TIME_DIFF" -lt "$COOLDOWN_MINUTES" ]; then
        exit 0
    fi
fi

# Créer un lock pour éviter les exécutions simultanées
if [ -f "$LOCK_FILE" ]; then
    exit 0
fi
touch "$LOCK_FILE"

# Analyser la dernière fenêtre de temps
TIME_AGO=$(date -d "$TIME_WINDOW minutes ago" '+%Y-%m-%d %H:%M')

# Compter les tentatives
ATTEMPTS=$(cat /var/log/mail.log /var/log/mail.log.1 2>/dev/null | \
    awk -v time_ago="$TIME_AGO" '$0 >= time_ago' | \
    grep "auth=0/1" | wc -l)

# Si le seuil est dépassé
if [ "$ATTEMPTS" -gt "$THRESHOLD_ATTEMPTS" ]; then
    HOSTNAME=$(hostname -f)
    PUBLIC_IP=$(curl -s ifconfig.me 2>/dev/null || echo "N/A")
    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Top 5 IPs avec géolocalisation
    TOP_IPS=$(cat /var/log/mail.log /var/log/mail.log.1 2>/dev/null | \
        awk -v time_ago="$TIME_AGO" '$0 >= time_ago' | \
        grep "auth=0/1" | \
        grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | \
        sort | uniq -c | sort -rn | head -5)
    
    # État Fail2ban
    BANNED_TOTAL=0
    for jail in postfix sasl dovecot sshd; do
        if fail2ban-client status "$jail" &>/dev/null; then
            BANNED=$(fail2ban-client status "$jail" 2>/dev/null | grep "Currently banned" | awk '{print $4}')
            BANNED_TOTAL=$((BANNED_TOTAL + BANNED))
        fi
    done
    
    # Taux d'attaque
    RATE_PER_MIN=$(echo "scale=1; $ATTEMPTS / $TIME_WINDOW" | bc 2>/dev/null || echo "N/A")
    EXCESS=$(( ATTEMPTS - THRESHOLD_ATTEMPTS ))
    
    # Génération du HTML
    cat > "$HTML_FILE" << 'HTMLEOF'
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Alerte Sécurité Mail</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%); padding: 20px; }
        .container { max-width: 800px; margin: 0 auto; background: white; border-radius: 16px; box-shadow: 0 20px 60px rgba(0, 0, 0, 0.4); overflow: hidden; }
        .header { background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%); color: white; padding: 30px; text-align: center; }
        .header h1 { font-size: 28px; font-weight: 700; margin-bottom: 8px; }
        .header p { font-size: 14px; opacity: 0.95; }
        .alert-banner { padding: 25px; background: #fee2e2; border-left: 5px solid #dc2626; color: #991b1b; font-weight: 600; font-size: 18px; }
        .content { padding: 30px; }
        .stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 15px; margin-bottom: 30px; }
        .stat-card { background: #fef3c7; border: 2px solid #f59e0b; border-radius: 10px; padding: 20px; text-align: center; }
        .stat-card.critical { background: #fee2e2; border-color: #dc2626; }
        .stat-number { font-size: 36px; font-weight: 700; color: #dc2626; margin-bottom: 5px; }
        .stat-label { font-size: 12px; color: #6b7280; text-transform: uppercase; }
        .section { margin-bottom: 25px; }
        .section-title { font-size: 18px; font-weight: 700; color: #1f2937; margin-bottom: 15px; padding-bottom: 8px; border-bottom: 2px solid #dc2626; }
        table { width: 100%; border-collapse: collapse; }
        thead { background: #dc2626; color: white; }
        th { padding: 12px; text-align: left; font-size: 11px; text-transform: uppercase; }
        td { padding: 12px; border-bottom: 1px solid #e5e7eb; font-size: 14px; }
        tr:hover { background: #fef3c7; }
        .actions { background: #f3f4f6; padding: 20px; border-radius: 10px; margin-top: 20px; }
        .actions h3 { font-size: 16px; margin-bottom: 10px; color: #dc2626; }
        .actions code { background: white; padding: 8px 12px; border-radius: 5px; display: block; margin: 5px 0; font-size: 13px; border: 1px solid #d1d5db; }
        .footer { background: #f9fafb; padding: 20px; text-align: center; color: #6b7280; font-size: 12px; border-top: 1px solid #e5e7eb; }
        .pulsing { animation: pulse 2s infinite; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.6; } }
    </style>
</head>
<body>
    <div class="container">
        <div class="header pulsing">
            <h1>🚨 ALERTE SÉCURITÉ MAIL</h1>
            <p>Attaque en cours détectée sur HOSTNAME_PLACEHOLDER</p>
        </div>
        <div class="alert-banner">
            ⚠️ Seuil d'alerte dépassé : EXCESS_PLACEHOLDER tentatives au-dessus de la limite
        </div>
        <div class="content">
            <div class="stat-grid">
                <div class="stat-card critical">
                    <div class="stat-number">ATTEMPTS_PLACEHOLDER</div>
                    <div class="stat-label">Tentatives (TIME_WINDOW_PLACEHOLDER min)</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">RATE_PLACEHOLDER</div>
                    <div class="stat-label">Tentatives/min</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">BANNED_PLACEHOLDER</div>
                    <div class="stat-label">IPs bannies</div>
                </div>
                <div class="stat-card critical">
                    <div class="stat-number">THRESHOLD_PLACEHOLDER</div>
                    <div class="stat-label">Seuil configuré</div>
                </div>
            </div>
            
            <div class="section">
                <h2 class="section-title">🎯 Top 5 IPs Attaquantes (Temps Réel)</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Adresse IP</th>
                            <th>Pays</th>
                            <th>Tentatives</th>
                        </tr>
                    </thead>
                    <tbody>
                        TOP_IPS_PLACEHOLDER
                    </tbody>
                </table>
            </div>
            
            <div class="section">
                <h2 class="section-title">🚫 État Fail2ban</h2>
                BANNED_LIST_PLACEHOLDER
            </div>
            
            <div class="actions">
                <h3>⚡ Actions Recommandées</h3>
                <p><strong>1. Vérifier les logs en temps réel :</strong></p>
                <code>sudo tail -f /var/log/mail.log | grep auth=0/1</code>
                
                <p><strong>2. Vérifier Fail2ban :</strong></p>
                <code>sudo fail2ban-client status postfix</code>
                
                <p><strong>3. Bloquer manuellement une IP :</strong></p>
                <code>sudo fail2ban-client set postfix banip X.X.X.X</code>
                
                <p><strong>4. Générer rapport complet :</strong></p>
                <code>sudo /root/mail_security_audit_html.sh</code>
            </div>
        </div>
        <div class="footer">
            <p><strong>Alerte générée le TIMESTAMP_PLACEHOLDER</strong></p>
            <p>Serveur : HOSTNAME_PLACEHOLDER (PUBLIC_IP_PLACEHOLDER)</p>
            <p>Mail Security Audit v1.3.1 • Prochaine alerte possible dans COOLDOWN_PLACEHOLDER minutes</p>
        </div>
    </div>
</body>
</html>
HTMLEOF

    # Remplacement des placeholders
    sed -i "s|HOSTNAME_PLACEHOLDER|$HOSTNAME|g" "$HTML_FILE"
    sed -i "s|PUBLIC_IP_PLACEHOLDER|$PUBLIC_IP|g" "$HTML_FILE"
    sed -i "s|TIMESTAMP_PLACEHOLDER|$TIMESTAMP|g" "$HTML_FILE"
    sed -i "s|ATTEMPTS_PLACEHOLDER|$ATTEMPTS|g" "$HTML_FILE"
    sed -i "s|TIME_WINDOW_PLACEHOLDER|$TIME_WINDOW|g" "$HTML_FILE"
    sed -i "s|RATE_PLACEHOLDER|$RATE_PER_MIN|g" "$HTML_FILE"
    sed -i "s|BANNED_PLACEHOLDER|$BANNED_TOTAL|g" "$HTML_FILE"
    sed -i "s|THRESHOLD_PLACEHOLDER|$THRESHOLD_ATTEMPTS|g" "$HTML_FILE"
    sed -i "s|EXCESS_PLACEHOLDER|$EXCESS|g" "$HTML_FILE"
    sed -i "s|COOLDOWN_PLACEHOLDER|$COOLDOWN_MINUTES|g" "$HTML_FILE"
    
    # Génération du tableau IPs avec géolocalisation
    TOP_IPS_HTML=""
    while IFS= read -r line; do
        if [ -n "$line" ]; then
            COUNT=$(echo "$line" | awk '{print $1}')
            IP=$(echo "$line" | awk '{print $2}')
            COUNTRY=$(get_country "$IP")
            TOP_IPS_HTML+="<tr><td><strong>$IP</strong></td><td>$COUNTRY</td><td>$COUNT</td></tr>"
        fi
    done <<< "$TOP_IPS"
    [ -z "$TOP_IPS_HTML" ] && TOP_IPS_HTML='<tr><td colspan="3" style="text-align:center;">Aucune IP identifiée</td></tr>'
    sed -i "s|TOP_IPS_PLACEHOLDER|$TOP_IPS_HTML|g" "$HTML_FILE"
    
    # Génération de la liste Fail2ban
    BANNED_LIST_HTML="<table><thead><tr><th>Jail</th><th>IPs Bannies</th></tr></thead><tbody>"
    HAS_BANNED=false
    for jail in postfix sasl dovecot sshd; do
        if fail2ban-client status "$jail" &>/dev/null; then
            IPS=$(fail2ban-client status "$jail" 2>/dev/null | grep "Banned IP list" | awk -F: '{print $2}' | xargs)
            if [ -n "$IPS" ] && [ "$IPS" != " " ]; then
                BANNED_LIST_HTML+="<tr><td><strong>$jail</strong></td><td>$IPS</td></tr>"
                HAS_BANNED=true
            fi
        fi
    done
    if [ "$HAS_BANNED" = false ]; then
        BANNED_LIST_HTML+='<tr><td colspan="2" style="text-align:center; color: #10b981;">Aucune IP bannie actuellement</td></tr>'
    fi
    BANNED_LIST_HTML+="</tbody></table>"
    sed -i "s|BANNED_LIST_PLACEHOLDER|$BANNED_LIST_HTML|g" "$HTML_FILE"
    
    # Envoi de l'alerte HTML
    if [ -n "$ALERT_EMAIL" ]; then
        if command -v mutt &> /dev/null; then
            mutt -e "set content_type=text/html" -s "🚨 [URGENT] Attaque Mail en cours - $HOSTNAME" "$ALERT_EMAIL" < "$HTML_FILE"
            date +%s > "$COOLDOWN_FILE"
            echo "$(date '+%Y-%m-%d %H:%M:%S') - Alerte HTML envoyée : $ATTEMPTS tentatives en $TIME_WINDOW min (taux: $RATE_PER_MIN/min)" >> /var/log/mail_audit.log
        elif command -v mail &> /dev/null; then
            # Fallback texte si mutt pas disponible
            SUBJECT="🚨 [URGENT] Attaque Mail - $HOSTNAME"
            MESSAGE="ALERTE: $ATTEMPTS tentatives en $TIME_WINDOW min (seuil: $THRESHOLD_ATTEMPTS)
Taux: $RATE_PER_MIN/min | IPs bannies: $BANNED_TOTAL
Voir le rapport complet sur le serveur."
            echo "$MESSAGE" | mail -s "$SUBJECT" "$ALERT_EMAIL"
            date +%s > "$COOLDOWN_FILE"
            echo "$(date '+%Y-%m-%d %H:%M:%S') - Alerte texte envoyée (mutt non installé)" >> /var/log/mail_audit.log
        else
            echo "$(date '+%Y-%m-%d %H:%M:%S') - ERREUR : ni mutt ni mail disponible" >> /var/log/mail_audit.log
        fi
    else
        echo "$(date '+%Y-%m-%d %H:%M:%S') - ERREUR : ALERT_EMAIL non configuré" >> /var/log/mail_audit.log
    fi
    
    # Nettoyage
    find /tmp -name "mail_alert_*.html" -mtime +7 -delete 2>/dev/null
else
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Vérification OK : $ATTEMPTS tentatives en $TIME_WINDOW min (seuil: $THRESHOLD_ATTEMPTS)" >> /var/log/mail_audit.log
fi

# Vérifications multiples avant suppression
if [ -f "$LOCK_FILE" ]; then                    # Le fichier existe ?
    if [ "$LOCK_FILE" = "/tmp/mail_alert.lock" ]; then  # C'est bien le bon fichier ?
        rm -f "$LOCK_FILE"                      # OK, on supprime
        echo "Lock file supprimé avec succès"
    else
        echo "ERREUR : LOCK_FILE a une valeur inattendue : $LOCK_FILE"
    fi
fi

exit 0