function typeText(elementId, text, delay = 100) {
    const element = document.getElementById(elementId);
    let index = 0;

    function type() {
        if (index < text.length) {
            element.textContent += text[index];
            index++;
            setTimeout(type, 1000);
        }
    }

    type();
}

// Lancer l'animation pour les deux textes
window.onload = function () {
    typeText("animated-text", "Bienvenue sur la page Admin Fabricant", 100);
    setTimeout(() => {
        typeText("animated-subtext", "Utilisez la barre de navigation pour accéder aux différentes fonctionnalités.", 50);
    }, 3000); // Délai avant de commencer le sous-texte
};