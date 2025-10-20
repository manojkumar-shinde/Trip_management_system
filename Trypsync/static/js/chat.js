// Chat client for group chat
document.addEventListener('DOMContentLoaded', () => {
  const chatEl = document.getElementById('chat');
  const groupId = chatEl.dataset.groupId;
  const currentUserId = parseInt(chatEl.dataset.currentUserId || '0', 10);
  // Try websocket first, fall back to polling. withCredentials=true sends cookies for session auth.
  const socket = io(window.location.origin, { transports: ['websocket', 'polling'], withCredentials: true, reconnection: true, reconnectionAttempts: 10, reconnectionDelay: 1000 });
  const messagesEl = document.getElementById('messages');
  const form = document.getElementById('chat-form');
  const input = document.getElementById('chat-input');
  const fileInput = document.getElementById('chat-file');
  const shareBtn = document.getElementById('share-location');
  const statusBadge = document.getElementById('chat-status');

  function addMessage(data){
    const li = document.createElement('li');
    const isMe = data.user_id === currentUserId;
    li.className = `chat-message ${isMe ? 'me' : 'them'}`;
    const time = new Date(data.timestamp).toLocaleString();
    let content = `<div class="meta"><strong>${data.user}</strong> <span class="time">${time}</span></div>`;
    if (data.media_filename){
      const url = `/static/uploads/${data.media_filename}`;
      content += `<div class="text"><img src="${url}" style="max-width:240px;border-radius:8px;"/></div>`;
    }
    if (data.location_lat && data.location_lng){
      const mapUrl = `https://www.google.com/maps?q=${data.location_lat},${data.location_lng}`;
      content += `<div class="text">📍 <a href="${mapUrl}" target="_blank">${data.location_label||'Shared location'}</a></div>`;
    }
    if (data.text){ content += `<div class="text">${data.text}</div>`; }
    li.innerHTML = content;
    messagesEl.appendChild(li);
    messagesEl.scrollTop = messagesEl.scrollHeight;
  }

  // fetch existing messages
  fetch(`/groups/${groupId}/messages`).then(r=>r.json()).then(data=>{
    if (data.error){
      const err = document.createElement('div'); err.textContent = data.error; messagesEl.appendChild(err); return;
    }
    data.forEach(m=> addMessage(m));
  });

  // run a quick diagnostic to see if cookies are sent
  fetch('/socket_diag').then(r=>r.json()).then(d=>{
    console.log('socket_diag', d);
  }).catch(e=>console.warn('socket_diag failed', e));

  socket.on('connect', () => {
    console.log('socket connected');
    try{ console.log('socket transport=', socket.io && socket.io.engine && socket.io.engine.transport && socket.io.engine.transport.name); }catch(e){console.log('transport inspect failed', e)}
    socket.emit('join', {group: groupId});
  });

  // disable send until server acknowledges join
  function setSendEnabled(enabled){
    const sendBtn = form.querySelector('button[type="submit"]');
    if (sendBtn) sendBtn.disabled = !enabled;
    input.disabled = !enabled;
  }
  setSendEnabled(false);

  socket.on('connect_error', (err) => {
    console.error('socket connect_error', err);
    // Attempt to detect which transport was attempted
    let attemptedTransport = 'unknown';
    try{
      if (socket && socket.io && socket.io.engine && socket.io.engine.transport && socket.io.engine.transport.name){
        attemptedTransport = socket.io.engine.transport.name;
      }
    }catch(e){ /* ignore */ }
    const li = document.createElement('li'); li.className='chat-error'; li.textContent = `Socket connection failed (${attemptedTransport}): ` + (err && err.message ? err.message : JSON.stringify(err)); messagesEl.appendChild(li);

    // fetch server-side diagnostic info to help root-cause analysis (cookies/headers)
    fetch('/socket_diag').then(r=>r.json()).then(d=>{
      console.log('socket_diag (from client connect_error):', d);
      const pre = document.createElement('pre'); pre.className='chat-diagnostic'; pre.textContent = JSON.stringify(d, null, 2);
      messagesEl.appendChild(pre);
      messagesEl.scrollTop = messagesEl.scrollHeight;
    }).catch(e=>{
      console.warn('socket_diag fetch failed', e);
    });

    // fallback: poll messages every 5s (only start once)
    if (!window._pollingMessages){
      window._pollingMessages = setInterval(()=>{
        fetch(`/groups/${groupId}/messages`).then(r=>r.json()).then(data=>{
          messagesEl.innerHTML = '';
          data.forEach(m=> addMessage(m));
        }).catch(e=>console.warn('polling fetch failed', e));
      }, 5000);
    }
  });

  socket.on('disconnect', (reason) => {
    console.warn('socket disconnected', reason);
    const li = document.createElement('li'); li.className='chat-status'; li.textContent = 'Disconnected from chat'; messagesEl.appendChild(li);
    if (statusBadge) statusBadge.textContent = 'Disconnected';
    setSendEnabled(false);
  });

  socket.on('message', (data) => { console.log('received message', data); addMessage(data); });
  socket.on('status', (data) => {
    const li = document.createElement('li'); li.className='chat-status'; li.textContent = data.message; messagesEl.appendChild(li); messagesEl.scrollTop = messagesEl.scrollHeight;
  });
  socket.on('joined', (data)=>{
    console.log('joined ack', data);
    if (statusBadge) statusBadge.textContent = 'Connected';
    setSendEnabled(true);
    const li = document.createElement('li'); li.className='chat-status'; li.textContent = 'You joined the chat'; messagesEl.appendChild(li); messagesEl.scrollTop = messagesEl.scrollHeight;
  });
  socket.on('left', (data)=>{
    if (statusBadge) statusBadge.textContent = 'Left';
    setSendEnabled(false);
    const li = document.createElement('li'); li.className='chat-status'; li.textContent = 'You left the chat'; messagesEl.appendChild(li); messagesEl.scrollTop = messagesEl.scrollHeight;
  });
  socket.on('error', (data) => {
    const li = document.createElement('li'); li.className='chat-error'; li.textContent = data.message || 'Socket error'; messagesEl.appendChild(li); messagesEl.scrollTop = messagesEl.scrollHeight;
  });

  form.addEventListener('submit', (e)=>{
    e.preventDefault();
    const text = input.value.trim();
    if (!text) return;
    socket.emit('message', {group: groupId, text});
    input.value = '';
  });

  // file upload handler
  fileInput.addEventListener('change', ()=>{
    const file = fileInput.files[0];
    if (!file) return;
    const fd = new FormData();
    fd.append('file', file);
    fetch(`/groups/${groupId}/upload`, {method:'POST', body:fd}).then(r=>r.json()).then(resp=>{
      console.log('upload resp', resp);
      fileInput.value = null;
    }).catch(e=>console.error(e));
  });

  // share location
  shareBtn.addEventListener('click', ()=>{
    if (!navigator.geolocation) { alert('Geolocation not supported'); return; }
    navigator.geolocation.getCurrentPosition(pos=>{
      const lat = pos.coords.latitude; const lng = pos.coords.longitude;
      const label = prompt('Add a label for this location (optional)');
      fetch(`/groups/${groupId}/share_location`, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({lat,lng,label})}).then(r=>r.json()).then(resp=>console.log('loc resp', resp));
    }, err=>{ alert('Could not get location'); });
  });

});