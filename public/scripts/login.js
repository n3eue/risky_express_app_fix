document.addEventListener('DOMContentLoaded', function () {
    const loginForm = document.querySelector('.form-l');
    const infoBulle = document.querySelector('.warn-info');

    // Effacer les champs au chargement
    document.getElementById('user-y').value = "";
    document.getElementById('pass-z').value = "";

    loginForm.addEventListener('submit', async (e) =>{
        e.preventDefault();

        const username = document.getElementById('user-y').value.trim();
        const password = document.getElementById('pass-z').value.trim();

        if (!username || !password) {
            infoBulle.textContent = 'Please fill in all fields.';
            infoBulle.classList.remove('hidden');
            return;
        }

        try {
            const response = await fetch('/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });

            if (!response.ok) {
                throw new Error(await response.text());
            }

            window.location.href = '/protected/index.html'; // Redirection après succès
        } catch (err) {
            infoBulle.textContent = err.message || 'Invalid username or password.';
            infoBulle.classList.remove('hidden');
        }
    });
});

