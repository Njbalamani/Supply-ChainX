/* SupplyChainX frontend interactions. */
(function () {
  'use strict';

  const toggle = document.getElementById('menuToggle');
  const sidebar = document.getElementById('sidebar');
  if (toggle && sidebar) {
    toggle.addEventListener('click', () => sidebar.classList.toggle('open'));
    document.addEventListener('click', (event) => {
      if (window.innerWidth <= 900 && sidebar.classList.contains('open') &&
          !sidebar.contains(event.target) && !toggle.contains(event.target)) {
        sidebar.classList.remove('open');
      }
    });
  }

  document.querySelectorAll('.alert').forEach((alert) => {
    window.setTimeout(() => {
      alert.style.transition = 'opacity .5s ease, transform .5s ease';
      alert.style.opacity = '0';
      alert.style.transform = 'translateY(-6px)';
    }, 6500);
  });

  function initCharts() {
    if (typeof Chart === 'undefined') return;
    document.querySelectorAll('canvas[data-chart]').forEach((canvas) => {
      let config;
      try { config = JSON.parse(canvas.dataset.chart); } catch (e) { return; }
      const base = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { labels: { color: '#8d95a6', boxWidth: 10, font: { size: 10 } } } },
        scales: {
          x: { ticks: { color: '#6f7889', font: { size: 10 } }, grid: { color: 'rgba(255,255,255,.045)' } },
          y: { ticks: { color: '#6f7889', font: { size: 10 } }, grid: { color: 'rgba(255,255,255,.045)' } }
        }
      };
      config.options = Object.assign(base, config.options || {});
      if (config.type === 'doughnut' || config.type === 'pie') {
        delete config.options.scales;
      }
      new Chart(canvas.getContext('2d'), config);
    });
  }

  function initNetwork() {
    const host = document.getElementById('networkStage');
    if (!host || typeof THREE === 'undefined') return;
    const endpoint = host.dataset.source;
    if (!endpoint) return;

    fetch(endpoint, { headers: { 'X-Requested-With': 'XMLHttpRequest' } })
      .then((response) => response.ok ? response.json() : Promise.reject(new Error('Graph unavailable')))
      .then((payload) => {
        const width = host.clientWidth || 600;
        const height = host.clientHeight || 320;
        const scene = new THREE.Scene();
        const camera = new THREE.PerspectiveCamera(58, width / height, 0.1, 1000);
        camera.position.set(0, 0, 46);
        const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });
        renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
        renderer.setSize(width, height);
        host.appendChild(renderer.domElement);

        const group = new THREE.Group();
        scene.add(group);
        scene.add(new THREE.AmbientLight(0xffffff, 0.75));
        const light = new THREE.PointLight(0xf0cd55, 1.4, 200);
        light.position.set(18, 24, 30);
        scene.add(light);

        const nodes = (payload.nodes || []).filter((n) => n.kind === 'package');
        const vulnerable = payload.vulnerable || {};
        const positions = {};
        const radius = Math.min(15, 5 + nodes.length * 0.45);
        nodes.forEach((node, index) => {
          const angle = (index / Math.max(1, nodes.length)) * Math.PI * 2;
          const tier = (index % 3) * 2.4;
          positions[node.id] = new THREE.Vector3(
            Math.cos(angle) * (radius + tier),
            Math.sin(angle) * (radius + tier) * 0.72,
            Math.sin(angle * 2.3) * 7
          );
        });

        nodes.forEach((node) => {
          const severity = vulnerable[node.id] || 'UNKNOWN';
          const color = severity === 'CRITICAL' || severity === 'HIGH' ? 0xff5d6c
            : severity === 'MEDIUM' ? 0xf0cd55 : 0x5aa9ff;
          const geometry = new THREE.SphereGeometry(severity === 'UNKNOWN' ? 0.75 : 1.15, 18, 18);
          const material = new THREE.MeshStandardMaterial({ color, emissive: color, emissiveIntensity: severity === 'UNKNOWN' ? 0.18 : 0.55, roughness: 0.35 });
          const mesh = new THREE.Mesh(geometry, material);
          mesh.position.copy(positions[node.id]);
          mesh.userData.node = node;
          group.add(mesh);
        });

        const lineMaterial = new THREE.LineBasicMaterial({ color: 0xc9a227, transparent: true, opacity: 0.22 });
        const hotMaterial = new THREE.LineBasicMaterial({ color: 0xff5d6c, transparent: true, opacity: 0.5 });
        (payload.edges || []).forEach((edge) => {
          if (!positions[edge.source] || !positions[edge.target]) return;
          const geometry = new THREE.BufferGeometry().setFromPoints([positions[edge.source], positions[edge.target]]);
          const vulnerableEdge = vulnerable[edge.target] && vulnerable[edge.target] !== 'UNKNOWN';
          group.add(new THREE.Line(geometry, vulnerableEdge ? hotMaterial : lineMaterial));
        });

        let dragging = false, previousX = 0, previousY = 0;
        host.addEventListener('pointerdown', (e) => { dragging = true; previousX = e.clientX; previousY = e.clientY; });
        window.addEventListener('pointerup', () => { dragging = false; });
        window.addEventListener('pointermove', (e) => {
          if (!dragging) return;
          group.rotation.y += (e.clientX - previousX) * 0.006;
          group.rotation.x += (e.clientY - previousY) * 0.004;
          previousX = e.clientX; previousY = e.clientY;
        });

        const resize = () => {
          const w = host.clientWidth, h = host.clientHeight;
          if (!w || !h) return;
          camera.aspect = w / h;
          camera.updateProjectionMatrix();
          renderer.setSize(w, h);
        };
        window.addEventListener('resize', resize);

        let frame = 0;
        function animate() {
          requestAnimationFrame(animate);
          frame += 0.006;
          if (!dragging) group.rotation.y += 0.0016;
          lineMaterial.opacity = 0.16 + Math.sin(frame) * 0.07;
          hotMaterial.opacity = 0.38 + Math.sin(frame * 1.7) * 0.16;
          group.children.forEach((child) => {
            if (child.isMesh) child.scale.setScalar(1 + Math.sin(frame * 2 + child.position.x) * 0.06);
          });
          renderer.render(scene, camera);
        }
        animate();
      })
      .catch(() => {
        host.innerHTML = '<div class="empty">Dependency graph unavailable for this scan.</div>';
      });
  }

  function pollScanStatus() {
    const element = document.querySelector('[data-scan-status]');
    if (!element) return;
    const scanId = element.dataset.scanStatus;
    const timer = window.setInterval(() => {
      fetch(`/scans/${scanId}/status/`, { headers: { 'X-Requested-With': 'XMLHttpRequest' } })
        .then((r) => r.ok ? r.json() : null)
        .then((data) => {
          if (!data) return;
          const badge = document.getElementById('scanStatusBadge');
          if (badge) badge.textContent = data.status;
          if (['COMPLETED', 'FAILED'].includes(data.status)) {
            window.clearInterval(timer);
            window.location.reload();
          }
        })
        .catch(() => window.clearInterval(timer));
    }, 2500);
  }

  document.addEventListener('DOMContentLoaded', () => {
    initCharts();
    initNetwork();
    pollScanStatus();
  });
})();
