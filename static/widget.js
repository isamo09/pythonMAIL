// widget.js
function loadEmailWidget() {
    fetch('/get_user_email')
        .then(response => response.json())
        .then(data => {
            if (data.email) {
                document.getElementById('emailWidget').innerHTML = `<p>Ваш email: ${data.email}</p>`;
            } else {
                document.getElementById('emailWidget').innerHTML = `<p>Вход не выполнен</p>`;
            }
        })
        .catch(error => {
            console.error('Ошибка при загрузке виджета:', error);
            document.getElementById('emailWidget').innerHTML = `<p>Ошибка загрузки виджета</p>`;
        });
}

// Загрузка виджета при загрузке страницы
document.addEventListener('DOMContentLoaded', loadEmailWidget);
