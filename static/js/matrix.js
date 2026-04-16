/**
 * AttackFlow — Matrix Rain + CRT Flicker + System Widgets.
 *
 * Modules:
 * 1. Matrix rain on <canvas> — cinematic green columns.
 * 2. CRT flicker — fast screen turn-on effect (replaces slow boot).
 * 3. System panel widgets — live clock, fake status bars, network log.
 * 4. Typewriter — animates elements with data-typewriter attribute.
 */
(function(){
'use strict';

var REDUCED = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

/* ── 1. MATRIX RAIN ────────────────────────────────────────── */
var canvas = document.getElementById('matrix-canvas');
if (canvas && !REDUCED) {
    var ctx    = canvas.getContext('2d');
    var cols   = [];
    var size   = 15;
    var fps    = 14;
    var iv     = 1000 / fps;
    var last   = 0;

    var chars  = 'ｦｧｨｩｪｫｬｭｮｯｰｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ0123456789@#&';

    function resize() {
        canvas.width  = window.innerWidth;
        canvas.height = window.innerHeight;
        var n = Math.floor(canvas.width / size);
        while (cols.length < n) cols.push(Math.floor(Math.random() * -20));
        cols.length = n;
    }

    function draw(t) {
        requestAnimationFrame(draw);
        if (t - last < iv) return;
        last = t;

        ctx.fillStyle = 'rgba(0,0,0,0.08)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.font = size + 'px monospace';

        for (var i = 0; i < cols.length; i++) {
            if (cols[i] < 0) { cols[i]++; continue; }
            var c = chars[Math.floor(Math.random() * chars.length)];
            var x = i * size;
            var y = cols[i] * size;

            ctx.fillStyle = '#aaffbb';
            ctx.fillText(c, x, y);

            if (cols[i] > 0) {
                ctx.fillStyle = 'rgba(32,194,14,0.6)';
                ctx.fillText(chars[Math.floor(Math.random() * chars.length)], x, y - size);
            }

            if (y > canvas.height && Math.random() > 0.975) {
                cols[i] = Math.floor(Math.random() * -10);
            }
            cols[i]++;
        }
    }

    resize();
    window.addEventListener('resize', resize);
    requestAnimationFrame(draw);
}

/* ── 2. CRT FLICKER (replaces boot sequence) ──────────────── */
var flicker = document.getElementById('flicker-overlay');
if (flicker) {
    // Check if user already saw the flicker this session
    var flickerSeen = sessionStorage.getItem('af_flicker');
    if (flickerSeen) {
        flicker.remove();
    } else {
        sessionStorage.setItem('af_flicker', '1');
        // Remove after animation ends (~450ms)
        setTimeout(function(){ flicker.remove(); }, 500);
    }
}

/* ── 3. SYSTEM PANEL WIDGETS ──────────────────────────────── */

// 3a. Live clock
var clockEl = document.getElementById('sys-clock');
var dateEl  = document.getElementById('sys-date');
if (clockEl) {
    function updateClock() {
        var now = new Date();
        var h = String(now.getHours()).padStart(2,'0');
        var m = String(now.getMinutes()).padStart(2,'0');
        var s = String(now.getSeconds()).padStart(2,'0');
        clockEl.textContent = h + ':' + m + ':' + s;
        if (dateEl) {
            var months = ['JAN','FEB','MAR','APR','MAY','JUN','JUL','AUG','SEP','OCT','NOV','DEC'];
            dateEl.textContent = now.getDate() + ' ' + months[now.getMonth()] + ' ' + now.getFullYear();
        }
    }
    updateClock();
    setInterval(updateClock, 1000);
}

// 3b. Fake system status bars (subtle random fluctuation)
var bars = document.querySelectorAll('[data-sys-bar]');
if (bars.length) {
    function updateBars() {
        bars.forEach(function(bar) {
            var base = parseInt(bar.getAttribute('data-sys-bar')) || 50;
            var val  = base + Math.floor(Math.random() * 16) - 8;
            val = Math.max(5, Math.min(98, val));
            var fill = bar.querySelector('.sys-bar-fill');
            var valEl = bar.querySelector('.sys-bar-val');
            if (fill) {
                fill.style.width = val + '%';
                fill.className = 'sys-bar-fill ' + (val > 85 ? 'bar-red' : val > 65 ? 'bar-amber' : 'bar-green');
            }
            if (valEl) valEl.textContent = val + '%';
        });
    }
    updateBars();
    setInterval(updateBars, 3000);
}

// 3c. Simulated network log
var logEl = document.getElementById('sys-log');
if (logEl) {
    var logMessages = [
        ['ok',   'DNS resolve ok'],
        ['ok',   'TLS handshake ok'],
        ['ok',   'Port scan idle'],
        ['ok',   'Worker heartbeat'],
        ['ok',   'DB pool: 8 conn'],
        ['ok',   'Redis ping ok'],
        ['ok',   'Celery beat sync'],
        ['ok',   'Cache hit ratio 94%'],
        ['warn', 'Retry queue: 2'],
        ['ok',   'Memory pool ok'],
        ['ok',   'Task queue clear'],
        ['ok',   'SSRF filter active'],
        ['ok',   'Rate limiter ok'],
        ['warn', 'Slow query 320ms'],
        ['ok',   'SSL cert valid'],
        ['ok',   'Conn pool refresh'],
    ];
    var MAX_LINES = 12;

    function addLogLine() {
        var msg = logMessages[Math.floor(Math.random() * logMessages.length)];
        var now = new Date();
        var time = String(now.getHours()).padStart(2,'0') + ':' +
                   String(now.getMinutes()).padStart(2,'0') + ':' +
                   String(now.getSeconds()).padStart(2,'0');

        var line = document.createElement('div');
        line.className = 'sys-log-line';
        line.innerHTML = '<span class="log-time">' + time + '</span> ' +
                         '<span class="log-' + msg[0] + '">[' + (msg[0] === 'ok' ? '+' : '!') + ']</span> ' +
                         msg[1];

        logEl.appendChild(line);

        // Keep max lines
        while (logEl.children.length > MAX_LINES) {
            logEl.removeChild(logEl.firstChild);
        }
    }

    // Initial fill (3 lines)
    addLogLine(); addLogLine(); addLogLine();
    // New line every 4-7 seconds
    setInterval(addLogLine, 4000 + Math.random() * 3000);
}

/* ── 4. TYPEWRITER ─────────────────────────────────────────── */
document.querySelectorAll('[data-typewriter]').forEach(function(el) {
    var text = el.textContent;
    el.textContent = '';
    el.style.visibility = 'visible';
    var idx = 0;
    var speed = parseInt(el.getAttribute('data-typewriter')) || 40;

    function type() {
        if (idx < text.length) {
            el.textContent += text[idx];
            idx++;
            setTimeout(type, speed + Math.random() * 30);
        }
    }
    setTimeout(type, 400);
});

})();
