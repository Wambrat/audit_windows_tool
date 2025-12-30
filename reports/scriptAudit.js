
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
    const details = document.querySelectorAll('.vulnerability-detail');
    
    items.forEach(item => {
        let show = true;
        
        // Filtre par statut (good/bad)
        if (activeFilters.status.length > 0) {
            const isGood = item.classList.contains('good');
            const isBad = item.classList.contains('bad');
            
            const statusMatches = (activeFilters.status.includes('good') && isGood) ||
                                (activeFilters.status.includes('bad') && isBad);
            if (!statusMatches) show = false;
        }
        
        // Filtre par automatisation
        if (show && activeFilters.automation.length > 0) {
            const automationStatus = item.getAttribute('data-automation');
            const automationMatches = (activeFilters.automation.includes('auto') && automationStatus === 'auto') ||
                                    (activeFilters.automation.includes('manual') && automationStatus === 'manual');
            if (!automationMatches) show = false;
        }
        
        item.style.display = show ? 'block' : 'none';
    });
    
    details.forEach(detail => {
        let show = true;
        
        // Filtre par statut (good/bad)
        if (activeFilters.status.length > 0) {
            const isGood = detail.classList.contains('good');
            const isBad = detail.classList.contains('bad');
            
            const statusMatches = (activeFilters.status.includes('good') && isGood) ||
                                (activeFilters.status.includes('bad') && isBad);
            if (!statusMatches) show = false;
        }
        
        // Filtre par automatisation
        if (show && activeFilters.automation.length > 0) {
            const automationStatus = detail.getAttribute('data-automation');
            const automationMatches = (activeFilters.automation.includes('auto') && automationStatus === 'auto') ||
                                    (activeFilters.automation.includes('manual') && automationStatus === 'manual');
            if (!automationMatches) show = false;
        }
        
        detail.style.display = show ? 'block' : 'none';
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
            const isGood = item.classList.contains('good');
            const isBad = item.classList.contains('bad');
            
            const statusMatches = (activeFilters.status.includes('good') && isGood) ||
                                (activeFilters.status.includes('bad') && isBad);
            if (!statusMatches) show = false;
        }
        
        if (show && activeFilters.automation.length > 0) {
            const automationStatus = item.getAttribute('data-automation');
            const automationMatches = (activeFilters.automation.includes('auto') && automationStatus === 'auto') ||
                                    (activeFilters.automation.includes('manual') && automationStatus === 'manual');
            if (!automationMatches) show = false;
        }
        
        item.style.display = show ? 'block' : 'none';
    });
    
    // Search in the Vulnerabilities Details and Recommendations section
    const details = document.querySelectorAll('.vulnerability-detail');
    details.forEach(detail => {
        const text = detail.textContent.toLowerCase();
        const matchesSearch = text.includes(searchTerm);
        
        // Appliquer les filtres existants en plus de la recherche
        let show = matchesSearch;
        
        if (show && activeFilters.status.length > 0) {
            const isGood = detail.classList.contains('good');
            const isBad = detail.classList.contains('bad');
            
            const statusMatches = (activeFilters.status.includes('good') && isGood) ||
                                (activeFilters.status.includes('bad') && isBad);
            if (!statusMatches) show = false;
        }
        
        if (show && activeFilters.automation.length > 0) {
            const automationStatus = detail.getAttribute('data-automation');
            const automationMatches = (activeFilters.automation.includes('auto') && automationStatus === 'auto') ||
                                    (activeFilters.automation.includes('manual') && automationStatus === 'manual');
            if (!automationMatches) show = false;
        }
        
        detail.style.display = show ? 'block' : 'none';
    });
});

document.querySelectorAll('.vulnerability-item').forEach(item => {
    item.classList.add('collapsed');
});
