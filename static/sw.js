// sw.js (place at project static root and serve it at "/sw.js")
self.addEventListener('push', event => {
  let payload = {};
  try { payload = event.data ? event.data.json() : {}; } catch (e) { payload = {}; }

  const title = payload.title || 'Notification';
  const options = {
    body: 'Notification', // fixed body per your request
    icon: payload.icon || '/static/default-avatar.png',
    badge: payload.badge || '/static/notification-badge.png',
    data: { url: payload.url || '/' }
  };

  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  const urlToOpen = event.notification.data && event.notification.data.url ? event.notification.data.url : '/';
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(windowClients => {
      for (let i = 0; i < windowClients.length; i++) {
        const client = windowClients[i];
        if (client.url === urlToOpen && 'focus' in client) return client.focus();
      }
      if (clients.openWindow) return clients.openWindow(urlToOpen);
    })
  );
});

self.addEventListener('message', event => {
  if (!event.data) return;
  if (event.data.type === 'TEST_PUSH') {
    const payload = event.data.payload || {};
    const title = payload.title || 'Test Notification';
    const options = {
      body: payload.body || 'This is a test!',
      icon: payload.icon || '/static/default-avatar.png',
      badge: payload.badge || '/static/notification-badge.png',
      data: { url: payload.url || '/' }
    };
    event.waitUntil(self.registration.showNotification(title, options));
  }
});
