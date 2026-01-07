# Audit Windows Tool

**Audit Windows Tool** est une solution complète basée sur PowerShell permettant d'auditer la sécurité des systèmes d'exploitation Windows (Postes de travail et Serveurs), de générer des rapports détaillés et d'appliquer des remédiations (durcissement) de manière sélective via une interface graphique.

## 📋 Fonctionnalités

L'outil analyse et évalue la configuration du système selon les bonnes pratiques de sécurité (inspiré des recommandations ANSSI / CIS). Il couvre les domaines suivants :

* **Contexte Système** : Détection du rôle (Serveur/Workstation), type de matériel (Physique/VM), et appartenance au domaine.
* **Sécurité des Comptes** :
    * Comptes Admin et Invité (activation/désactivation).
    * Configuration LAPS.
    * Politiques de mots de passe (Locales et AD).
    * Niveau d'authentification (Windows Hello, etc.).
    * Configuration UAC (User Account Control).
    * Groupes locaux (détection des membres suspects).
* **Sécurité Réseau** :
    * Statut IPv6, LLMNR et NetBIOS (prévention du poisoning).
    * Configuration du Pare-feu Windows.
    * Analyse des interfaces et profils VPN.
* **Sécurité de l'OS (Hardening)** :
    * BitLocker (état du chiffrement).
    * Credential Guard, Device Guard (VBS/HVCI).
    * Exploit Protection (DEP, ASLR, CFG).
    * Attack Surface Reduction (ASR rules).
    * AppLocker et SRP.
    * Protection LSASS et gestion des hashs LM.
* **Services et Applications** :
    * Sécurité RDP (NLA, chiffrement RPC).
    * Configuration WinRM et SMB (détection SMBv1).
    * État des mises à jour Windows et applications installées.
* **Journalisation (Logging)** :
    * Taille et rétention des journaux d'événements.
    * Configuration de l'Event Forwarding et présence d'agents SIEM.

## 🚀 Prérequis

* **Système d'exploitation** : Windows 10/11 ou Windows Server 2016/2019/2022.
* **Privilèges** : Le script demandera automatiquement l'élévation de privilèges (Exécuter en tant qu'administrateur).
* **PowerShell** : Version 5.1 ou supérieure (support WPF requis pour l'interface).
* **Politique d'exécution** : Le script tente de contourner la politique (`-ExecutionPolicy Bypass`), mais assurez-vous de pouvoir exécuter des scripts.

## 📂 Structure du Projet

```text
audit_windows_tool/
│
├── Modules/
│   └── AuditCore/         # Le cœur du moteur d'audit (scripts de vérification)
│
├── auditResults/          # Dossier de sortie des résultats bruts (JSON)
├── xml/                   # Dossier de sortie des fichiers de remédiation (XML)
├── reports/               # Scripts de génération HTML et rapports finaux
│   ├── audits/            # Rapports HTML d'audit
│   └── remediations/      # Rapports HTML de remédiation
│
├── run.ps1                # 🟢 Point d'entrée unique (Interface graphique)
├── Start-Audit.ps1        # Script d'audit (appelé par run.ps1)
├── Start-Remediation.ps1  # Script de remédiation (appelé par run.ps1)
└── audit.log              # Journal d'exécution
```

## 🛠️ Utilisation Simplifiée

L'outil utilise une interface graphique centralisée pour guider l'utilisateur à travers les étapes d'audit et de correction.

### 1. Lancer l'outil

1.  Ouvrez le dossier contenant les scripts.
2.  Faites un clic droit sur `run.ps1` et choisissez **Exécuter avec PowerShell**.
    * *Note : Vous n'avez pas besoin de l'exécuter en tant qu'administrateur manuellement, l'outil demandera l'élévation de privilèges au moment opportun.*

### 2. Choisir le mode

Une fenêtre "Mode selection" s'ouvre. Choisissez l'une des options :

#### 🔍 Mode Audit (Recommandé en premier)
Sélectionnez **Audit** puis cliquez sur **Run**.
1.  Le script d'audit se lance et analyse le système.
2.  À la fin de l'analyse, des fenêtres contextuelles vous proposeront successivement :
    * De générer et ouvrir le **rapport HTML d'audit** (situé dans `reports/audits/`).
    * De basculer directement vers le **mode Remédiation**.
    * De générer le rapport des actions correctives si vous avez appliqué des corrections.

#### 🛡️ Mode Remédiation
Sélectionnez **Remediation** puis cliquez sur **Run**.
1.  Sélectionnez le fichier XML de résultats (généré lors de l'audit précédent dans le dossier `xml/`).
2.  Une interface s'ouvre pour vous permettre de cocher les éléments à corriger.
3.  Cliquez sur **Apply** pour lancer les corrections.
4.  À la fermeture, l'outil vous proposera de générer le **rapport HTML de remédiation** (situé dans `reports/remediations/`).

## 📊 Rapports

Les rapports HTML sont générés automatiquement si vous validez les demandes à la fin de l'exécution :
* **Audit Report** : Vue d'ensemble de l'état de sécurité avec codes couleurs (PASS/FAIL/WARNING).
* **Remediation Report** : Synthèse des actions correctives appliquées (Succès/Erreur).

## ⚠️ Avertissement

Cet outil effectue des modifications profondes sur la configuration de sécurité (Registre, Services, GPO locales).

1.  **Sauvegarde** : Faites toujours une sauvegarde ou un point de restauration avant d'appliquer des remédiations.
2.  **Test** : Ne lancez jamais de remédiation massive sur un environnement de production sans avoir testé au préalable sur une machine de pré-production.
3.  **Responsabilité** : L'utilisation de cet outil est sous votre entière responsabilité. Les auteurs ne peuvent être tenus responsables d'éventuels dysfonctionnements suite au durcissement du système.