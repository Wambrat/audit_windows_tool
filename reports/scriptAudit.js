
// Dictionnaire de traductions
const translations = {
    'en': {
        'security-score': 'Security Score',
        'based-controls': 'Based on the number of valid security controls',
        'system-info': 'System Information',
        'computer-name': 'Computer Name',
        'operating-system': 'Operating System',
        'report-date': 'Report Date',
        'vuln-summary': 'Vulnerabilities Summary',
        'search-placeholder': 'Search for a vulnerability...',
        'vulnerabilities': 'Vulnerabilities',
        'remediations': 'Remediations',
        'automatic': 'Automatic',
        'manual': 'Manual',
        'compliant': 'Compliant',
        'non-compliant': 'Non Compliant',
        'semi-compliant': 'Semi-Compliant',
        'unknown': 'Unknown',
        'category': 'Category',
        'comments': 'Comments',
        'recommendation': 'Recommendation',
        'additional-details': 'Additional Details'
    },
    'fr': {
        'security-score': 'Score de S&eacute;curit&eacute;',
        'based-controls': 'Bas&eacute; sur le nombre de contr&ocirc;les de s&eacute;curit&eacute; valides',
        'system-info': 'Informations Syst&egrave;me',
        'computer-name': 'Nom de l&apos;Ordinateur',
        'operating-system': 'Syst&egrave;me d&apos;Exploitation',
        'report-date': 'Date du Rapport',
        'vuln-summary': 'R&eacute;sum&eacute; des Vuln&eacute;rabilit&eacute;s',
        'search-placeholder': 'Rechercher une vulnérabilité...',
        'vulnerabilities': 'Vuln&eacute;rabilit&eacute;s',
        'remediations': 'R&eacute;m&eacute;diations',
        'automatic': 'Automatique',
        'manual': 'Manuel',
        'compliant': 'Conforme',
        'non-compliant': 'Non Conforme',
        'semi-compliant': 'Partiellement Conforme',
        'unknown': 'Inconnu',
        'category': 'Cat&eacute;gorie',
        'comments': 'Commentaires',
        'recommendation': 'Recommandation',
        'additional-details': 'D&eacute;tails Suppl&eacute;mentaires'
    }
};

let currentLanguage = 'fr';

function changeLanguage(lang) {
    currentLanguage = lang;
    
    // Update all elements with data attributes
    document.querySelectorAll('[data-en][data-fr]').forEach(elem => {
        if (lang === 'en') {
            elem.textContent = elem.getAttribute('data-en');
        } else {
            elem.textContent = elem.getAttribute('data-fr');
        }
    });
    
    // Update placeholders and other dynamic content
    const searchBox = document.getElementById('searchInput');
    if (searchBox) {
        searchBox.placeholder = translations[lang]['search-placeholder'];
    }
    
    localStorage.setItem('preferredLanguage', lang);
}

// Load preferred language on page load
document.addEventListener('DOMContentLoaded', function() {
    const savedLanguage = localStorage.getItem('preferredLanguage') || 'fr';
    const selector = document.getElementById('languageSelector');
    if (selector) {
        selector.value = savedLanguage;
        changeLanguage(savedLanguage);
    }
});

function toggleDetails(element) {
    const details = element.querySelector('.details');
    details.style.display = details.style.display === 'none' ? 'block' : 'none';
}

// État des filtres
const activeFilters = {
    status: [],
    automation: []
};

// Gestion des clics sur les boutons de filtre
document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', function() {
        const filterType = this.getAttribute('data-filter');
        const filterValue = this.getAttribute('data-value');
        
        // Toggle l'état du bouton
        this.classList.toggle('active');
        
        // Mise à jour de l'état des filtres
        if (this.classList.contains('active')) {
            if (!activeFilters[filterType].includes(filterValue)) {
                activeFilters[filterType].push(filterValue);
            }
        } else {
            activeFilters[filterType] = activeFilters[filterType].filter(v => v !== filterValue);
        }
        
        applyFilters();
    });
});

// Fonction de filtrage
function applyFilters() {
    const items = document.querySelectorAll('.vulnerability-item');
    
    items.forEach(item => {
        let show = true;
        
        // Filtre par statut (pass/fail/warning/unknown)
        if (activeFilters.status.length > 0) {
            const isPass = item.classList.contains('pass');
            const isFail = item.classList.contains('fail');
            const isWarning = item.classList.contains('warning');
            const isUnknown = item.classList.contains('unknown');
            
            const statusMatches = (activeFilters.status.includes('good') && isPass) ||
                                (activeFilters.status.includes('warning') && isWarning) ||
                                (activeFilters.status.includes('bad') && isFail) ||
                                (activeFilters.status.includes('unknown') && isUnknown);
            if (!statusMatches) show = false;
        }
        
        // Filtre par automatisation
        if (show && activeFilters.automation.length > 0) {
            const automationStatus = item.getAttribute('data-automation');
            const isAutoTrue = automationStatus === 'True' || automationStatus === 'true';
            const automationMatches = (activeFilters.automation.includes('auto') && isAutoTrue) ||
                                    (activeFilters.automation.includes('manual') && !isAutoTrue);
            if (!automationMatches) show = false;
        }
        
        item.style.display = show ? 'block' : 'none';
    });
}

document.getElementById('searchInput').addEventListener('keyup', function() {
    const searchTerm = this.value.toLowerCase();
    
    // Search in the Vulnerabilities Summary section
    const items = document.querySelectorAll('.vulnerability-item');
    items.forEach(item => {
        const text = item.textContent.toLowerCase();
        const matchesSearch = text.includes(searchTerm);
        
        // Appliquer les filtres existants en plus de la recherche
        let show = matchesSearch;
        
        if (show && activeFilters.status.length > 0) {
            const isPass = item.classList.contains('pass');
            const isFail = item.classList.contains('fail');
            const isWarning = item.classList.contains('warning');
            const isUnknown = item.classList.contains('unknown');
            
            const statusMatches = (activeFilters.status.includes('good') && (isPass || isWarning)) ||
                                (activeFilters.status.includes('bad') && isFail) ||
                                (activeFilters.status.includes('unknown') && isUnknown);
            if (!statusMatches) show = false;
        }
        
        if (show && activeFilters.automation.length > 0) {
            const automationStatus = item.getAttribute('data-automation');
            const isAutoTrue = automationStatus === 'True' || automationStatus === 'true';
            const automationMatches = (activeFilters.automation.includes('auto') && isAutoTrue) ||
                                    (activeFilters.automation.includes('manual') && !isAutoTrue);
            if (!automationMatches) show = false;
        }
        
        item.style.display = show ? 'block' : 'none';
    });
});

document.querySelectorAll('.vulnerability-item').forEach(item => {
    item.classList.add('collapsed');
});
// Fonction pour toggle les détails supplémentaires
function toggleAdditionalDetails(button) {
    const content = button.nextElementSibling;
    const isHidden = content.style.display === 'none';
    
    content.style.display = isHidden ? 'block' : 'none';
    button.setAttribute('aria-expanded', isHidden);
}

// Initialiser l'état des boutons
document.querySelectorAll('.details-toggle').forEach(btn => {
    btn.setAttribute('aria-expanded', 'false');
});