document.addEventListener("DOMContentLoaded", () => {
    const taskGrid = document.getElementById("task-grid");
    const searchInput = document.getElementById("search");
    const logoutBtn = document.getElementById("logout-btn");

    let tasks = [];

    // Fonction pour récupérer les tâches de l'utilisateur depuis le backend
    async function fetchTasks() {
        try {
            const response = await fetch('/tasks');
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            const data = await response.json();
            tasks = data;
            displayTasks();
        } catch (error) {
            console.error('Error fetching tasks:', error);
        }
    }

    // Fonction pour afficher les tâches
    function displayTasks(filteredTasks = tasks) {
        taskGrid.innerHTML = "";
        filteredTasks.forEach(task => {
            const taskCard = document.createElement("div");
            taskCard.classList.add("task-card");
            taskCard.innerHTML = `
                <h3>${task.task}</h3>
                <button class="delete-btn" data-id="${task.id}">🗑️  Delete</button>
            `;
            taskGrid.appendChild(taskCard);
        });
    }

    // Filtrage des tâches
    searchInput.addEventListener("input", () => {
        const query = searchInput.value.toLowerCase();
        const filteredTasks = tasks.filter(task =>
            task.task.toLowerCase().includes(query)
        );
        displayTasks(filteredTasks);
    });

    // Suppression des tâches
    taskGrid.addEventListener("click", async (event) => {
        if (event.target.classList.contains("delete-btn")) {
            const taskId = event.target.getAttribute("data-id");
            try {
                const response = await fetch(`/tasks/${taskId}`, {
                    method: 'DELETE'
                });
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                tasks = tasks.filter(task => task.id != taskId);
                displayTasks();
            } catch (error) {
                console.error('Error deleting task:', error);
            }
        }
    });

    // Logout (exemple, ajuster selon backend)
    logoutBtn.addEventListener("click", () => {
        alert("Logging out...");
        window.location.href = "/logout";
    });

    // Récupérer et afficher les tâches au chargement
    fetchTasks();
});
