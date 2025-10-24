// static/push-client.js
// Exposes initPushForCurrentUser() to subscribe & send subscription to server.
// (Does NOT auto-run — we call it from your main client after identify)
async function initPushForCurrentUser() {
  if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
    console.warn('Push not supported');
    return;
  }
  try {
    const swReg = await navigator.serviceWorker.register('/static/sw.js');
    console.log('SW registered', swReg);

    const perm = await Notification.requestPermission();
    if (perm !== 'granted') {
      console.log('Notification permission not granted:', perm);
      return;
    }

    const keyRes = await fetch('/api/vapid_public', { credentials: 'same-origin' });
    if (!keyRes.ok) { console.warn('vapid public key fetch failed'); return; }
    const keyJson = await keyRes.json();
    const publicKey = keyJson.publicKey || keyJson.publicKey || keyJson.publicKey; // defensive
    const vapidPublicKey = urlBase64ToUint8Array(publicKey);

    const sub = await swReg.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: vapidPublicKey
    });

    await fetch('/api/save_push_sub', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ subscription: sub })
    });

    console.log('Push subscription saved');
  } catch (err) {
    console.error('initPush error', err);
  }
}

function urlBase64ToUint8Array(base64String) {
  const padding = '='.repeat((4 - base64String.length % 4) % 4);
  const base64 = (base64String + padding).replace(/\-/g, '+').replace(/_/g, '/');
  const rawData = window.atob(base64);
  const outputArray = new Uint8Array(rawData.length);
  for (let i = 0; i < rawData.length; ++i) outputArray[i] = rawData.charCodeAt(i);
  return outputArray;
}

// expose globally
window.initPushForCurrentUser = initPushForCurrentUser;
