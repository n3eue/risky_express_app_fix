document.addEventListener('DOMContentLoaded', () => {
    const registerForm = document.querySelector('.form-l');
    const infoBulle = document.querySelector('.log_info_check');

    // Effacer les champs au chargement
    document.getElementById('user-y').value = "";
    document.getElementById('pass-z').value = "";
    document.getElementById('pass-confirm').value = "";

    registerForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        const username = document.getElementById('user-y').value.trim();
        const password = document.getElementById('pass-z').value.trim();
        const confirmPassword = document.getElementById('pass-confirm').value.trim();

        if (!username || !password || !confirmPassword) {
            infoBulle.textContent = 'Please fill in all fields.';
            infoBulle.classList.remove('hidden');
            return;
        }

        if (password !== confirmPassword) {
            infoBulle.textContent = 'Passwords do not match.';
            infoBulle.classList.remove('hidden');
            return;
        }

        try {
            const response = await fetch('/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });

            if (!response.ok) {
                throw new Error(await response.text());
            }

            window.location.href = '/public/login.html'; // Redirection après succès
        } catch (err) {
            infoBulle.textContent = err.message || 'Registration failed.';
            infoBulle.classList.remove('hidden');
        }
    });
});
