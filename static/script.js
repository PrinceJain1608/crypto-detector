document.addEventListener('DOMContentLoaded', (event) => {
    const form = document.querySelector('form');
    if (form) {
        form.addEventListener('submit', () => {
            document.getElementById('progress-bar').style.display = 'block';
            setInterval(() => {
                fetch('/progress')
                    .then(response => response.json())
                    .then(data => {
                        document.querySelector('.progress-bar').style.width = data.progress + '%';
                    });
            }, 1000);
        });
    }
});

// Include Chart.js for visualizations
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>