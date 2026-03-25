(function () {
    var cfg = window.AIChatConfig || {};
    var botId = cfg.botId;
    if (!botId) return;
  
    var API = (cfg.serverUrl || 'http://localhost:3000').replace(/\/$/, '');
  
    // Validate UUID trước khi dùng
    var UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    var _stored = sessionStorage.getItem('ai_session_' + botId) || '';
    var sessionId = UUID_RE.test(_stored) ? _stored : null;
  
    var wsocket = null;
    var operatorActive = false;
    var _msgs = null; // ref toàn cục trong widget
  
    fetch(API + '/api/widget/bot/' + encodeURIComponent(botId))
      .then(function (r) { return r.json(); })
      .then(function (botData) {
        if (!botData || botData.error) return;
        injectWidget(botData);
      })
      .catch(function () {});
  
    // ===== XSS SAFE =====
    function escapeHtml(str) {
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    }
  
    // ===== SOCKET =====
    function initSocket(onReady) {
      if (window.io) { onReady(); return; }
      var sc = document.createElement('script');
      sc.src = API + '/socket.io/socket.io.js';
      sc.onload = onReady;
      sc.onerror = function () {};
      document.head.appendChild(sc);
    }
  
    function connectSocket() {
      if (wsocket) return;
      wsocket = window.io(API, {
        transports: ['websocket', 'polling'],
        reconnectionAttempts: 5,
        reconnectionDelay: 2000,
      });
  
      wsocket.on('connect', function () {
        if (sessionId) wsocket.emit('widget:join', { sessionId: sessionId });
      });
  
      // Reconnect lại join room
      wsocket.on('reconnect', function () {
        if (sessionId) wsocket.emit('widget:join', { sessionId: sessionId });
      });
  
      wsocket.on('message:new', function (data) {
        if (!_msgs || data.sessionId !== sessionId) return;
        if (data.role === 'operator') {
          removeTyping();
          addMsg('👨‍💼 ' + escapeHtml(data.content), 'operator-msg');
        }
      });
  
      wsocket.on('agent:joined', function (data) {
        if (!_msgs) return;
        operatorActive = true;
        removeTyping();
        addMsg('✅ ' + escapeHtml(data.message), 'bot');
        setStatus('👨‍💼 Đang kết nối với nhân viên', true);
      });
  
      wsocket.on('agent:left', function (data) {
        if (!_msgs) return;
        operatorActive = false;
        addMsg('🤖 ' + escapeHtml(data.message), 'bot');
        setStatus('● Đang hoạt động', false);
      });
  
      wsocket.on('connect_error', function () {});
      wsocket.on('disconnect', function () {});
    }
  
    function removeTyping() {
      if (!_msgs) return;
      var t = _msgs.querySelector('._aicw-typing');
      if (t) t.remove();
    }
  
    // addMsg / setStatus khai báo sau injectWidget gán _msgs
    function addMsg(html, type) {
      if (!_msgs) return null;
      var el = document.createElement('div');
      el.className = '_aicw-msg ' + type;
      el.innerHTML = html; // đã escape trước khi truyền vào
      _msgs.appendChild(el);
      _msgs.scrollTop = _msgs.scrollHeight;
      return el;
    }
  
    function setStatus(text, isOp) {
      var statusEl = document.getElementById('_aicw-status');
      if (!statusEl) return;
      statusEl.textContent = text;
      statusEl.classList.toggle('operator', !!isOp);
    }
  
    // ===== INJECT WIDGET =====
    function injectWidget(bot) {
      // Validate color/position tránh CSS injection
      var c   = /^#[0-9a-fA-F]{3,6}$/.test(bot.primary_color) ? bot.primary_color : '#2563eb';
      var pos = bot.position === 'left' ? 'left' : 'right';
  
      var s = document.createElement('style');
      s.textContent = `
        #_aicw-btn{position:fixed;bottom:24px;${pos}:24px;width:56px;height:56px;border-radius:50%;
          background:${c};border:none;cursor:pointer;box-shadow:0 4px 20px rgba(0,0,0,.25);
          z-index:2147483646;display:flex;align-items:center;justify-content:center;
          transition:transform .2s,box-shadow .2s;font-size:24px;}
        #_aicw-btn:hover{transform:scale(1.08);box-shadow:0 6px 28px rgba(0,0,0,.3);}
        #_aicw-box{position:fixed;bottom:90px;${pos}:16px;width:370px;max-width:calc(100vw - 32px);
          height:500px;max-height:80vh;background:#fff;border-radius:18px;
          box-shadow:0 12px 48px rgba(0,0,0,.18);display:none;flex-direction:column;
          z-index:2147483647;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
          overflow:hidden;animation:_aicw-pop .22s cubic-bezier(.34,1.56,.64,1);}
        #_aicw-box.open{display:flex;}
        @keyframes _aicw-pop{from{opacity:0;transform:scale(.92) translateY(16px)}to{opacity:1;transform:scale(1) translateY(0)}}
        ._aicw-head{background:${c};color:#fff;padding:14px 16px;
          display:flex;align-items:center;justify-content:space-between;flex-shrink:0;}
        ._aicw-head-info{display:flex;align-items:center;gap:10px;}
        ._aicw-avatar{width:36px;height:36px;border-radius:50%;background:rgba(255,255,255,.2);
          display:flex;align-items:center;justify-content:center;font-size:20px;}
        ._aicw-name{font-weight:700;font-size:15px;}
        ._aicw-status{font-size:11px;opacity:.8;margin-top:1px;}
        ._aicw-status.operator{opacity:1;font-weight:600;}
        ._aicw-close{background:none;border:none;color:#fff;cursor:pointer;padding:6px;
          border-radius:8px;opacity:.8;font-size:18px;line-height:1;}
        ._aicw-close:hover{opacity:1;background:rgba(255,255,255,.15);}
        ._aicw-msgs{flex:1;overflow-y:auto;padding:16px;display:flex;flex-direction:column;
          gap:10px;scroll-behavior:smooth;}
        ._aicw-msgs::-webkit-scrollbar{width:4px;}
        ._aicw-msgs::-webkit-scrollbar-thumb{background:#ddd;border-radius:4px;}
        ._aicw-msg{max-width:84%;padding:10px 14px;border-radius:16px;font-size:14px;
          line-height:1.55;word-break:break-word;}
        ._aicw-msg.bot{background:#f1f3f5;color:#1a1a1a;align-self:flex-start;border-bottom-left-radius:4px;}
        ._aicw-msg.user{background:${c};color:#fff;align-self:flex-end;border-bottom-right-radius:4px;}
        ._aicw-msg.operator-msg{background:#fef9c3;color:#1a1a1a;align-self:flex-start;
          border-bottom-left-radius:4px;border-left:3px solid #f59e0b;}
        ._aicw-typing span{display:inline-block;width:7px;height:7px;border-radius:50%;
          background:#aaa;margin:0 2px;animation:_aicw-bounce 1.2s infinite;}
        ._aicw-typing span:nth-child(2){animation-delay:.2s;}
        ._aicw-typing span:nth-child(3){animation-delay:.4s;}
        @keyframes _aicw-bounce{0%,80%,100%{transform:translateY(0)}40%{transform:translateY(-6px)}}
        ._aicw-foot{padding:12px 14px;border-top:1px solid #f0f0f0;display:flex;gap:8px;
          align-items:flex-end;flex-shrink:0;}
        #_aicw-input{flex:1;border:1.5px solid #e5e7eb;border-radius:10px;padding:9px 12px;
          font-size:14px;resize:none;max-height:80px;outline:none;font-family:inherit;
          transition:border-color .2s;line-height:1.4;}
        #_aicw-input:focus{border-color:${c};}
        #_aicw-send{background:${c};color:#fff;border:none;border-radius:10px;
          padding:9px 16px;cursor:pointer;font-size:14px;font-weight:600;white-space:nowrap;}
        #_aicw-send:hover{opacity:.88;}
        #_aicw-send:disabled{opacity:.45;cursor:not-allowed;}
        ._aicw-powered{text-align:center;font-size:10px;color:#ccc;padding:4px 0 8px;flex-shrink:0;}
      `;
      document.head.appendChild(s);
  
      var btn = document.createElement('button');
      btn.id = '_aicw-btn';
      btn.setAttribute('aria-label', 'Mở chat');
      btn.textContent = bot.bot_avatar || '🤖';
  
      var box = document.createElement('div');
      box.id = '_aicw-box';
      // Escape tên bot tránh XSS
      box.innerHTML = [
        '<div class="_aicw-head">',
          '<div class="_aicw-head-info">',
            '<div class="_aicw-avatar">' + escapeHtml(bot.bot_avatar || '🤖') + '</div>',
            '<div>',
              '<div class="_aicw-name">' + escapeHtml(bot.name) + '</div>',
              '<div class="_aicw-status" id="_aicw-status">● Đang hoạt động</div>',
            '</div>',
          '</div>',
          '<button class="_aicw-close" id="_aicw-close" aria-label="Đóng">✕</button>',
        '</div>',
        '<div class="_aicw-msgs" id="_aicw-msgs"></div>',
        '<div class="_aicw-foot">',
          '<textarea id="_aicw-input" rows="1" placeholder="Nhập tin nhắn..." maxlength="1000"></textarea>',
          '<button id="_aicw-send">Gửi</button>',
        '</div>',
        '<div class="_aicw-powered">Powered by Thuong Mai Phi</div>'
      ].join('');
  
      document.body.appendChild(btn);
      document.body.appendChild(box);
  
      _msgs   = document.getElementById('_aicw-msgs');
      var input   = document.getElementById('_aicw-input');
      var sendBtn = document.getElementById('_aicw-send');
      var isLoading = false;
      var isOpen = false;
  
      // Init socket sau khi _msgs đã sẵn sàng
      initSocket(function () { connectSocket(); });
  
      function addTyping() {
        var el = document.createElement('div');
        el.className = '_aicw-msg bot _aicw-typing';
        el.innerHTML = '<span></span><span></span><span></span>';
        _msgs.appendChild(el);
        _msgs.scrollTop = _msgs.scrollHeight;
        return el;
      }
  
      function toggleChat() {
        isOpen = !isOpen;
        box.classList.toggle('open', isOpen);
        if (isOpen && _msgs.children.length === 0) {
          addMsg(escapeHtml(bot.welcome_message || 'Xin chào!'), 'bot');
        }
        if (isOpen) setTimeout(function () { input.focus(); }, 150);
      }
  
      function send() {
        var text = input.value.trim();
        // Giới hạn 1000 ký tự + chống double submit
        if (!text || isLoading || text.length > 1000) return;
  
        addMsg(escapeHtml(text), 'user');
        input.value = '';
        input.style.height = 'auto';
        isLoading = true;
        sendBtn.disabled = true;
  
        var typing = addTyping();
  
        fetch(API + '/api/widget/chat', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ message: text, sessionId: sessionId, botId: botId })
        })
        .then(function (r) {
          if (!r.ok) return r.json().then(function (d) { throw new Error(d.error || r.status); });
          return r.json();
        })
        .then(function (data) {
          // Lưu sessionId mới + join room
          if (data.sessionId && UUID_RE.test(data.sessionId) && data.sessionId !== sessionId) {
            sessionId = data.sessionId;
            sessionStorage.setItem('ai_session_' + botId, sessionId);
            if (wsocket) wsocket.emit('widget:join', { sessionId: sessionId });
          }
  
          // Operator mode: giữ typing, chờ nhân viên reply qua socket
          if (data.operatorMode) {
            typing.innerHTML = '<span></span><span></span><span></span>';
            typing.className = '_aicw-msg bot _aicw-typing';
            return;
          }
  
          // AI reply
          typing.className = '_aicw-msg bot';
          typing.innerHTML = '';
          typing.textContent = data.reply || '...';
        })
        .catch(function () {
          typing.className = '_aicw-msg bot';
          typing.innerHTML = '';
          typing.textContent = 'Xin lỗi, có lỗi xảy ra. Vui lòng thử lại!';
        })
        .finally(function () {
          isLoading = false;
          sendBtn.disabled = false;
          input.focus();
        });
      }
  
      btn.addEventListener('click', toggleChat);
      document.getElementById('_aicw-close').addEventListener('click', toggleChat);
      sendBtn.addEventListener('click', send);
      input.addEventListener('keydown', function (e) {
        if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); }
      });
      input.addEventListener('input', function () {
        this.style.height = 'auto';
        this.style.height = Math.min(this.scrollHeight, 80) + 'px';
      });
    }
  })();