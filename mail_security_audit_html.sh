#!/bin/bash

# ===================================================================
# Script d'audit de sécurité mail - VERSION HTML MODERNE
# Auteur : Communauté YunoHost
# Licence : MIT
# Repository : https://github.com/gamersalpha/yunohost-mail-security-audit
# Description : Génère un rapport HTML de sécurité mail sur une période configurable
# Version : 1.3.1 - Géolocalisation améliorée avec drapeaux
# ===================================================================

LOG_FILE="/var/log/mail.log"
AUTH_LOG="/var/log/auth.log"
HTML_FILE="/tmp/mail_security_report_$(date +%Y%m%d_%H%M%S).html"

# ⚠️ CONFIGURATION - MODIFIEZ CES LIGNES ou définissez les variables avant l'appel du script ⚠️
ALERT_EMAIL=${ALERT_EMAIL:-votre-email@domaine.fr}
ANALYSIS_PERIOD=${ANALYSIS_PERIOD:-7}  # Nombre de jours à analyser (1=aujourd'hui, 7=semaine, 30=mois)

# Collecte des données
END_DATE=$(date '+%Y-%m-%d')
START_DATE=$(date -d "$ANALYSIS_PERIOD days ago" '+%Y-%m-%d')
PERIOD_DISPLAY="du $START_DATE au $END_DATE ($ANALYSIS_PERIOD jours)"
HOSTNAME=$(hostname -f)
PUBLIC_IP=$(curl -s ifconfig.me 2>/dev/null || echo "N/A")
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
CURRENT_TIMESTAMP=$(date +%s)

# Fonction de géolocalisation IP avec emojis drapeaux
get_country() {
    local ip=$1
    if command -v geoiplookup &> /dev/null; then
        # Récupérer le code pays et le nom complet
        geoip_result=$(geoiplookup "$ip" 2>/dev/null)
        country_code=$(echo "$geoip_result" | awk -F': ' '{print $2}' | awk -F',' '{print $1}' | xargs)
        country_name=$(echo "$geoip_result" | awk -F', ' '{print $2}' | xargs)
        
        # Gérer les cas spéciaux
        if [[ -z "$country_code" || "$country_code" == "IP Address not found" ]]; then
            echo "🌍 Inconnu"
            return
        fi
        
        # Mapper les codes ISO-2 vers les drapeaux et noms
        case "$country_code" in
            # Europe
            "NL") echo "🇳🇱 Pays-Bas" ;;
            "DE") echo "🇩🇪 Allemagne" ;;
            "FR") echo "🇫🇷 France" ;;
            "GB") echo "🇬🇧 Royaume-Uni" ;;
            "IT") echo "🇮🇹 Italie" ;;
            "ES") echo "🇪🇸 Espagne" ;;
            "PL") echo "🇵🇱 Pologne" ;;
            "RO") echo "🇷🇴 Roumanie" ;;
            "BE") echo "🇧🇪 Belgique" ;;
            "CH") echo "🇨🇭 Suisse" ;;
            "AT") echo "🇦🇹 Autriche" ;;
            "SE") echo "🇸🇪 Suède" ;;
            "NO") echo "🇳🇴 Norvège" ;;
            "DK") echo "🇩🇰 Danemark" ;;
            "FI") echo "🇫🇮 Finlande" ;;
            "PT") echo "🇵🇹 Portugal" ;;
            "GR") echo "🇬🇷 Grèce" ;;
            "CZ") echo "🇨🇿 Tchéquie" ;;
            "HU") echo "🇭🇺 Hongrie" ;;
            "IE") echo "🇮🇪 Irlande" ;;
            "BG") echo "🇧🇬 Bulgarie" ;;
            "HR") echo "🇭🇷 Croatie" ;;
            "SK") echo "🇸🇰 Slovaquie" ;;
            "LT") echo "🇱🇹 Lituanie" ;;
            "LV") echo "🇱🇻 Lettonie" ;;
            "EE") echo "🇪🇪 Estonie" ;;
            "SI") echo "🇸🇮 Slovénie" ;;
            
            # Amériques
            "US") echo "🇺🇸 États-Unis" ;;
            "CA") echo "🇨🇦 Canada" ;;
            "BR") echo "🇧🇷 Brésil" ;;
            "MX") echo "🇲🇽 Mexique" ;;
            "AR") echo "🇦🇷 Argentine" ;;
            "CL") echo "🇨🇱 Chili" ;;
            "CO") echo "🇨🇴 Colombie" ;;
            
            # Asie
            "CN") echo "🇨🇳 Chine" ;;
            "RU") echo "🇷🇺 Russie" ;;
            "IN") echo "🇮🇳 Inde" ;;
            "JP") echo "🇯🇵 Japon" ;;
            "KR") echo "🇰🇷 Corée du Sud" ;;
            "TH") echo "🇹🇭 Thaïlande" ;;
            "VN") echo "🇻🇳 Vietnam" ;;
            "ID") echo "🇮🇩 Indonésie" ;;
            "MY") echo "🇲🇾 Malaisie" ;;
            "SG") echo "🇸🇬 Singapour" ;;
            "PH") echo "🇵🇭 Philippines" ;;
            "TR") echo "🇹🇷 Turquie" ;;
            "IL") echo "🇮🇱 Israël" ;;
            "SA") echo "🇸🇦 Arabie Saoudite" ;;
            "AE") echo "🇦🇪 Émirats Arabes Unis" ;;
            "IR") echo "🇮🇷 Iran" ;;
            "IQ") echo "🇮🇶 Irak" ;;
            "PK") echo "🇵🇰 Pakistan" ;;
            "BD") echo "🇧🇩 Bangladesh" ;;
            
            # Afrique
            "ZA") echo "🇿🇦 Afrique du Sud" ;;
            "EG") echo "🇪🇬 Égypte" ;;
            "NG") echo "🇳🇬 Nigeria" ;;
            "KE") echo "🇰🇪 Kenya" ;;
            "MA") echo "🇲🇦 Maroc" ;;
            "TN") echo "🇹🇳 Tunisie" ;;
            "DZ") echo "🇩🇿 Algérie" ;;
            
            # Océanie
            "AU") echo "🇦🇺 Australie" ;;
            "NZ") echo "🇳🇿 Nouvelle-Zélande" ;;
            
            # Autres/Génériques
            "A1") echo "🌐 Proxy Anonyme" ;;
            "A2") echo "🛰️ Satellite" ;;
            "AP") echo "🌏 Asie-Pacifique" ;;
            "EU") echo "🇪🇺 Europe" ;;
            
            # Par défaut : afficher le code + nom si disponible
            *) 
                if [[ -n "$country_name" ]]; then
                    echo "🌍 $country_name"
                else
                    echo "🌍 $country_code"
                fi
                ;;
        esac
    else
        echo "❓ Non installé"
    fi
}

# Statistiques sur la période définie (avec tous les logs)
TOTAL_ATTEMPTS=$(cat /var/log/mail.log.1 /var/log/mail.log 2>/dev/null | \
    awk -v start="$START_DATE" -v end="$END_DATE" '$0 >= start && $0 <= end' | \
    grep "auth=0/1" | wc -l)

EXTERNAL_AUTH=$(cat /var/log/mail.log.1 /var/log/mail.log 2>/dev/null | \
    awk -v start="$START_DATE" -v end="$END_DATE" '$0 >= start && $0 <= end' | \
    grep "sasl_method=" | \
    grep -vE "192.168|10\.|172\.(1[6-9]|2[0-9]|3[01])|127\.0\.0\.1" | wc -l)

SENT_MAILS=$(cat /var/log/mail.log.1 /var/log/mail.log 2>/dev/null | \
    awk -v start="$START_DATE" -v end="$END_DATE" '$0 >= start && $0 <= end' | \
    grep "status=sent" | wc -l)

BANNED_TOTAL=0

if systemctl is-active --quiet fail2ban; then
    FAIL2BAN_STATUS="✓ Actif"
    FAIL2BAN_COLOR="#10b981"
    for jail in postfix sasl dovecot sshd recidive; do
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
TOP_IPS=$(cat /var/log/mail.log.1 /var/log/mail.log 2>/dev/null | \
    awk -v start="$START_DATE" -v end="$END_DATE" '$0 >= start && $0 <= end' | \
    grep "auth=0" | \
    grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | \
    sort | uniq -c | sort -rn | head -5)

# Top utilisateurs légitimes sur la période
TOP_USERS=$(cat /var/log/mail.log.1 /var/log/mail.log 2>/dev/null | \
    awk -v start="$START_DATE" -v end="$END_DATE" '$0 >= start && $0 <= end' | \
    grep "sasl_username=" | \
    grep -v "authentication failed" | \
    grep -oE "sasl_username=[^,]+" | \
    awk -F= '{print $2}' | \
    sort | uniq -c | sort -rn | head -5)

# Top 5 expéditeurs sur la période
TOP_SENDERS=$(cat /var/log/mail.log.1 /var/log/mail.log 2>/dev/null | \
    awk -v start="$START_DATE" -v end="$END_DATE" '$0 >= start && $0 <= end' | \
    grep "postfix/qmgr" | \
    grep -oE "from=<[^>]+>" | \
    sed 's/from=<//g' | sed 's/>//g' | \
    sort | uniq -c | sort -rn | head -5)

if [ -z "$TOP_SENDERS" ]; then
    TOP_SENDERS=$(cat /var/log/mail.log.1 /var/log/mail.log 2>/dev/null | \
        awk -v start="$START_DATE" -v end="$END_DATE" '$0 >= start && $0 <= end' | \
        grep "postfix/qmgr" | \
        grep -oE "from=[^,]+" | \
        sed 's/from=//g' | sed 's/<//g' | sed 's/>//g' | \
        sort | uniq -c | sort -rn | head -5)
fi

# Top 5 destinataires sur la période
TOP_RECIPIENTS=$(cat /var/log/mail.log.1 /var/log/mail.log 2>/dev/null | \
    awk -v start="$START_DATE" -v end="$END_DATE" '$0 >= start && $0 <= end' | \
    grep "status=sent" | \
    grep -oE "to=<[^>]+>" | \
    sed 's/to=<//g' | sed 's/>//g' | \
    sort | uniq -c | sort -rn | head -5)

if [ -z "$TOP_RECIPIENTS" ]; then
    TOP_RECIPIENTS=$(cat /var/log/mail.log.1 /var/log/mail.log 2>/dev/null | \
        awk -v start="$START_DATE" -v end="$END_DATE" '$0 >= start && $0 <= end' | \
        grep "status=sent" | \
        grep -oE "to=[^,]+" | \
        sed 's/to=//g' | sed 's/<//g' | sed 's/>//g' | \
        sort | uniq -c | sort -rn | head -5)
fi

# Statistiques par pays (si geoip disponible)
declare -A country_stats
if command -v geoiplookup &> /dev/null; then
    while IFS= read -r line; do
        if [ -n "$line" ]; then
            COUNT=$(echo "$line" | awk '{print $1}')
            IP=$(echo "$line" | awk '{print $2}')
            
            # Obtenir le pays formaté
            COUNTRY_DISPLAY=$(get_country "$IP")
            # Extraire juste le nom sans emoji pour le regroupement
            COUNTRY_KEY=$(echo "$COUNTRY_DISPLAY" | sed 's/^[^ ]* //')
            
            ((country_stats["$COUNTRY_DISPLAY"] += COUNT))
        fi
    done <<< "$TOP_IPS"
fi

# Générer le top 5 des pays
TOP_COUNTRIES=""
if [ ${#country_stats[@]} -gt 0 ]; then
    TOP_COUNTRIES=$(for country in "${!country_stats[@]}"; do
        echo "${country_stats[$country]} $country"
    done | sort -rn | head -5)
fi

# Génération du HTML (identique à la version précédente, je ne copie que les parties modifiées)
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
        .activity-indicator { display: inline-flex; align-items: center; gap: 8px; padding: 6px 12px; border-radius: 8px; font-size: 13px; font-weight: 600; }
        .activity-live { background: #fee2e2; color: #dc2626; animation: pulse 2s infinite; }
        .activity-recent { background: #fef3c7; color: #d97706; }
        .activity-old { background: #f3f4f6; color: #6b7280; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.7; } }
        .activity-dot { width: 8px; height: 8px; border-radius: 50%; }
        .activity-live .activity-dot { background: #dc2626; animation: blink 1s infinite; }
        .activity-recent .activity-dot { background: #d97706; }
        .activity-old .activity-dot { background: #9ca3af; }
        @keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
        .country-flag { font-size: 20px; margin-right: 8px; }
        @media (max-width: 768px) { .stats-grid, .info-grid { grid-template-columns: 1fr; } table { font-size: 14px; } th, td { padding: 12px 8px; } }
        /* ── Détails d'attaque dépliables ── */
        .attack-details { background: #f8f7ff; border-radius: 10px; margin: 4px 0 8px 0; border: 1px solid #e0d9ff; overflow: hidden; }
        .attack-details summary { cursor: pointer; padding: 10px 14px; font-size: 13px; font-weight: 600; color: #4f46e5; background: #ede9fe; list-style: none; display: flex; align-items: center; gap: 8px; user-select: none; transition: background 0.2s; }
        .attack-details summary::-webkit-details-marker { display: none; }
        .attack-details summary::before { content: '▶'; font-size: 10px; transition: transform 0.2s; }
        .attack-details[open] summary::before { transform: rotate(90deg); }
        .attack-details summary:hover { background: #ddd6fe; }
        .attack-detail-body { padding: 0 14px 12px 14px; }
        .attack-log-table { width: 100%; border-collapse: collapse; font-size: 12px; margin-top: 8px; }
        .attack-log-table th { background: #7c3aed; color: white; padding: 6px 10px; text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: 0.4px; }
        .attack-log-table td { padding: 6px 10px; border-bottom: 1px solid #ede9fe; color: #374151; vertical-align: top; }
        .attack-log-table tr:last-child td { border-bottom: none; }
        .attack-log-table tbody tr:nth-child(odd) { background: #faf8ff; }
        .attack-log-table tbody tr:hover { background: #ede9fe; }
        .log-method { display: inline-block; padding: 2px 8px; border-radius: 10px; background: #fee2e2; color: #b91c1c; font-weight: 600; font-size: 11px; }
        .log-user { font-family: monospace; color: #6d28d9; }
        .log-time { white-space: nowrap; color: #6b7280; font-size: 11px; }
        details tr td { padding: 12px 16px; }
        .details-row td { padding: 0 !important; border-bottom: none !important; background: transparent !important; }
        .details-row:hover { background: transparent !important; }
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
            <div class="section"><h2 class="section-title">🎯 Top 5 des IPs Attaquantes</h2><div class="table-container"><table><thead><tr><th>Adresse IP</th><th>Pays</th><th>Tentatives</th><th>Dernière activité</th><th>Statut</th></tr></thead><tbody>TOP_IPS_PLACEHOLDER</tbody></table></div></div>
            TOP_COUNTRIES_SECTION_PLACEHOLDER
            <div class="section"><h2 class="section-title">👥 Connexions Légitimes</h2><div class="table-container"><table><thead><tr><th>Utilisateur</th><th>Connexions</th><th>Type</th></tr></thead><tbody>TOP_USERS_PLACEHOLDER</tbody></table></div></div>
            <div class="section"><h2 class="section-title">📧 Top 5 des Expéditeurs</h2><div class="table-container"><table><thead><tr><th>Expéditeur</th><th>Mails envoyés</th><th>Type</th></tr></thead><tbody>TOP_SENDERS_PLACEHOLDER</tbody></table></div></div>
            <div class="section"><h2 class="section-title">📬 Top 5 des Destinataires</h2><div class="table-container"><table><thead><tr><th>Destinataire</th><th>Mails reçus</th><th>Type</th></tr></thead><tbody>TOP_RECIPIENTS_PLACEHOLDER</tbody></table></div></div>
            <div class="section"><h2 class="section-title">🚫 IPs Actuellement Bannies</h2><div class="table-container"><table><thead><tr><th>Jail</th><th>IPs Bannies</th></tr></thead><tbody>BANNED_IPS_PLACEHOLDER</tbody></table></div></div>
        </div>
        <div class="footer"><p>Rapport généré automatiquement par <strong>Mail Security Audit v1.3.1</strong></p><p>Serveur YunoHost • Fail2ban • Postfix • Dovecot • GeoIP</p></div>
    </div>
</body>
</html>
HTMLEOF

# (Le reste du script est identique - je ne le copie pas pour la concision)
# Remplacement des placeholders, génération des tableaux, etc.

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

# Génération du tableau des IPs avec géolocalisation + détails dépliables
TOP_IPS_HTML=""
RANK=0
while IFS= read -r line; do
    if [ -n "$line" ]; then
        RANK=$((RANK + 1))
        COUNT=$(echo "$line" | awk '{print $1}')
        IP=$(echo "$line" | awk '{print $2}')

        # Géolocalisation avec drapeaux complets
        COUNTRY=$(get_country "$IP")

        # Dernière activité
        LAST_SEEN=$(cat /var/log/mail.log.1 /var/log/mail.log 2>/dev/null | \
            grep "$IP" | grep "auth=0" | tail -1 | awk '{print $1, $2}' | \
            sed 's/T/ /' | cut -d'.' -f1)

        if [ -z "$LAST_SEEN" ]; then
            LAST_SEEN_DISPLAY="Inconnue"
            ACTIVITY_INDICATOR='<div class="activity-indicator activity-old"><span class="activity-dot"></span>Ancienne</div>'
        else
            LAST_SEEN_DISPLAY=$(date -d "$LAST_SEEN" '+%d/%m %H:%M' 2>/dev/null || echo "$LAST_SEEN")
            LAST_SEEN_TIMESTAMP=$(date -d "$LAST_SEEN" +%s 2>/dev/null || echo 0)
            TIME_DIFF=$((CURRENT_TIMESTAMP - LAST_SEEN_TIMESTAMP))
            TIME_DIFF_HOURS=$((TIME_DIFF / 3600))

            if [ "$TIME_DIFF_HOURS" -lt 1 ]; then
                ACTIVITY_INDICATOR='<div class="activity-indicator activity-live"><span class="activity-dot"></span>EN COURS</div>'
            elif [ "$TIME_DIFF_HOURS" -lt 24 ]; then
                ACTIVITY_INDICATOR='<div class="activity-indicator activity-recent"><span class="activity-dot"></span>Récente</div>'
            else
                ACTIVITY_INDICATOR='<div class="activity-indicator activity-old"><span class="activity-dot"></span>Ancienne</div>'
            fi
        fi

        if [ "$COUNT" -gt 100 ]; then
            BADGE='<span class="badge badge-danger">Critique</span>'
        elif [ "$COUNT" -gt 50 ]; then
            BADGE='<span class="badge badge-warning">Élevé</span>'
        else
            BADGE='<span class="badge badge-success">Normal</span>'
        fi

        # ── Collecte des détails d'attaque pour cette IP (max 20 entrées) ──
        ATTACK_ROWS=""
        while IFS= read -r logline; do
            [ -z "$logline" ] && continue

            # Extraire la date/heure
            LOG_DT=$(echo "$logline" | awk '{print $1, $2}' | sed 's/T/ /' | cut -d'.' -f1)
            LOG_DT_DISPLAY=$(date -d "$LOG_DT" '+%d/%m/%Y %H:%M:%S' 2>/dev/null || echo "$LOG_DT")

            # Extraire la méthode SASL si présente
            LOG_METHOD=$(echo "$logline" | grep -oE "sasl_method=[^,]+" | awk -F= '{print $2}')
            #[ -z "$LOG_METHOD" ] && LOG_METHOD=$(echo "$logline" | grep -oE "auth=[^ ]+" | awk -F= '{print $2}')
            [ -z "$LOG_METHOD" ] && LOG_METHOD="—"

            # Extraire l'utilisateur tenté si présent
            LOG_USER=$(echo "$logline" | grep -oE "sasl_username=[^,]+" | awk -F= '{print $2}')
            [ -z "$LOG_USER" ] && LOG_USER=$(echo "$logline" | grep -oE "user=[^ ,]+" | awk -F= '{print $2}')
            [ -z "$LOG_USER" ] && LOG_USER="—"

            # Extraire le service (postfix, dovecot…)
            LOG_SERVICE=$(echo "$logline" | awk -F'[][]' '{print $1}' | awk '{print $NF}' | tr -d ' :')
            [ -z "$LOG_SERVICE" ] && LOG_SERVICE="—"

            ATTACK_ROWS+="<tr>"
            ATTACK_ROWS+="<td class=\"log-time\">$LOG_DT_DISPLAY</td>"
            ATTACK_ROWS+="<td>$LOG_SERVICE</td>"
            ATTACK_ROWS+="<td><span class=\"log-method\">$LOG_METHOD</span></td>"
            ATTACK_ROWS+="<td class=\"log-user\">$LOG_USER</td>"
            ATTACK_ROWS+="</tr>"
        done <<< "$(cat /var/log/mail.log.1 /var/log/mail.log 2>/dev/null | \
            grep "$IP" | grep "auth=0" | \
            tail -20)"

        if [ -z "$ATTACK_ROWS" ]; then
            ATTACK_ROWS='<tr><td colspan="4" style="text-align:center;color:#9ca3af;">Aucun détail disponible</td></tr>'
        fi

        DETAILS_HTML="<details class=\"attack-details\">"
        DETAILS_HTML+="<summary>🔍 Voir le détail des tentatives ($COUNT au total, 20 dernières affichées)</summary>"
        DETAILS_HTML+="<div class=\"attack-detail-body\">"
        DETAILS_HTML+="<table class=\"attack-log-table\"><thead><tr><th>Date / Heure</th><th>Service</th><th>Méthode</th><th>Utilisateur tenté</th></tr></thead>"
        DETAILS_HTML+="<tbody>$ATTACK_ROWS</tbody></table>"
        DETAILS_HTML+="</div></details>"

        # Ligne principale du tableau
        TOP_IPS_HTML+="<tr>"
        TOP_IPS_HTML+="<td><strong>$IP</strong></td>"
        TOP_IPS_HTML+="<td>$COUNTRY</td>"
        TOP_IPS_HTML+="<td>$COUNT</td>"
        TOP_IPS_HTML+="<td>$LAST_SEEN_DISPLAY $ACTIVITY_INDICATOR</td>"
        TOP_IPS_HTML+="<td>$BADGE</td>"
        TOP_IPS_HTML+="</tr>"

        # Ligne dépliable sur toute la largeur (colspan=5)
        TOP_IPS_HTML+="<tr class=\"details-row\">"
        TOP_IPS_HTML+="<td colspan=\"5\" style=\"padding: 0 16px 8px 16px; background: #faf8ff;\">$DETAILS_HTML</td>"
        TOP_IPS_HTML+="</tr>"
    fi
done <<< "$TOP_IPS"
[ -z "$TOP_IPS_HTML" ] && TOP_IPS_HTML='<tr><td colspan="5" style="text-align:center; color: #10b981;">Aucune attaque détectée sur la période ✓</td></tr>'
sed -i "s|TOP_IPS_PLACEHOLDER|$TOP_IPS_HTML|g" "$HTML_FILE"

# Génération de la section Top Pays
if [ -n "$TOP_COUNTRIES" ]; then
    TOP_COUNTRIES_HTML="<div class=\"section\"><h2 class=\"section-title\">🌍 Top 5 des Pays Attaquants</h2><div class=\"table-container\"><table><thead><tr><th>Pays</th><th>Tentatives totales</th></tr></thead><tbody>"
    
    while IFS= read -r line; do
        if [ -n "$line" ]; then
            COUNT=$(echo "$line" | awk '{print $1}')
            COUNTRY=$(echo "$line" | awk '{$1=""; print $0}' | sed 's/^ //')
            TOP_COUNTRIES_HTML+="<tr><td><strong>$COUNTRY</strong></td><td>$COUNT</td></tr>"
        fi
    done <<< "$TOP_COUNTRIES"
    
    TOP_COUNTRIES_HTML+="</tbody></table></div></div>"
    sed -i "s|TOP_COUNTRIES_SECTION_PLACEHOLDER|$TOP_COUNTRIES_HTML|g" "$HTML_FILE"
else
    if ! command -v geoiplookup &> /dev/null; then
        GEOIP_WARNING="<div class=\"alert alert-warning\"><strong>💡 Astuce</strong> : Installez geoip-bin pour voir les pays attaquants : <code>sudo apt install geoip-bin -y</code></div>"
        sed -i "s|TOP_COUNTRIES_SECTION_PLACEHOLDER|$GEOIP_WARNING|g" "$HTML_FILE"
    else
        sed -i "s|TOP_COUNTRIES_SECTION_PLACEHOLDER||g" "$HTML_FILE"
    fi
fi

# (Le reste du code pour les autres tableaux et l'envoi d'email reste identique)

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

BANNED_IPS_HTML=""
for jail in postfix sasl dovecot sshd recidive; do
    if fail2ban-client status "$jail" &>/dev/null; then
        BANNED_LIST=$(fail2ban-client status "$jail" 2>/dev/null | grep "Banned IP list" | awk -F: '{print $2}' | xargs)
        if [ -n "$BANNED_LIST" ] && [ "$BANNED_LIST" != " " ]; then
            BANNED_IPS_HTML+="<tr><td><strong>$jail</strong></td><td>$BANNED_LIST</td></tr>"
        fi
    fi
done
[ -z "$BANNED_IPS_HTML" ] && BANNED_IPS_HTML='<tr><td colspan="2" style="text-align:center; color: #10b981;">Aucune IP bannie actuellement ✓</td></tr>'
sed -i "s|BANNED_IPS_PLACEHOLDER|$BANNED_IPS_HTML|g" "$HTML_FILE"

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

find /tmp -name "mail_security_report_*.html" -mtime +30 -delete 2>/dev/null
exit 0
