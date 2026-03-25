# Chatbox AI Agents

## Cài đặt

```bash
npm install
cp .env.example .env
# Điền JWT_SECRET, OPENAI_API_KEY vào .env
node server.js
```

## Deploy với PM2

```bash
npm install -g pm2
pm2 start ecosystem.config.js --env production
pm2 save && pm2 startup
```