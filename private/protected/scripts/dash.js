document.addEventListener("DOMContentLoaded", () => {
    const taskForm = document.getElementById("task-form");
    const taskInput = document.getElementById("task-input");
    const taskContainer = document.getElementById("task-container");
    const logoutBtn = document.getElementById("logout-btn");

    // Charger les tâches
    const loadTasks = async () => {
        try {
            const response = await fetch("/tasks");
            if (!response.ok) throw new Error("Failed to fetch tasks");
            const tasks = await response.json();
            taskContainer.innerHTML = "";
            tasks.forEach(addTaskToUI);
        } catch (error) {
            console.error("Error loading tasks:", error);
        }
    };

    // Ajouter une tâche à l'UI
    const addTaskToUI = (task) => {
        const taskCard = document.createElement("div");
        taskCard.classList.add("task-card");
        taskCard.innerHTML = `
            <span>${task.task}</span>
            <button class="delete-btn" data-id="${task.id}">Delete</button>
        `;
        taskContainer.appendChild(taskCard);
    };

    // Soumission du formulaire pour ajouter une tâche
    taskForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const taskText = taskInput.value.trim();
        if (!taskText) return;

        try {
            const response = await fetch("/add", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ task: taskText })
            });

            if (!response.ok) throw new Error("Failed to add task");

            taskInput.value = "";
            loadTasks();
        } catch (error) {
            console.error("Error adding task:", error);
        }
    });

    // Suppression d'une tâche
    taskContainer.addEventListener("click", async (e) => {
        if (!e.target.classList.contains("delete-btn")) return;

        const taskId = e.target.getAttribute("data-id");

        try {
            const response = await fetch(`/tasks/${taskId}`, { method: "DELETE" });
            if (!response.ok) throw new Error("Failed to delete task");

            loadTasks();
        } catch (error) {
            console.error("Error deleting task:", error);
        }
    });

    // Déconnexion
    logoutBtn.addEventListener("click", async () => {
        try {
            await fetch("/logout");
            window.location.href = "/public/login.html";
        } catch (error) {
            console.error("Error logging out:", error);
        }
    });

    loadTasks();
});
