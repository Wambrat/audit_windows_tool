
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