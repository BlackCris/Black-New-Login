const express = require('express');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const fs = require('fs');
const session = require('express-session');
const path = require('path');

const app = express();
const port = 3000;
const usersFilePath = path.join(__dirname, 'users.json');
const blockedUsersFilePath = path.join(__dirname, 'blockedUsers.json');
const loginAttempts = {}; // { ip: { count: Number, unlockTime: Date } }

const LOGIN_ATTEMPT_LIMIT = 3; // 尝试限制次数
const LOCK_TIME = 3 * 60 * 1000; // 锁定时间

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public'));
app.use(session({
  secret: 'secret',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // HTTPS环境下应设为true
}));

// 初始化用户文件
const initializeUsersFile = () => {
  if (!fs.existsSync(usersFilePath) || fs.readFileSync(usersFilePath).length === 0) {
    fs.writeFileSync(usersFilePath, JSON.stringify([], null, 2));
    console.log('Users file initialized.');
  }

  if (!fs.existsSync(blockedUsersFilePath)) {
    fs.writeFileSync(blockedUsersFilePath, JSON.stringify([], null, 2));
    console.log('Blocked users file initialized.');
  }
};

// 认证中间件
function requireLogin(req, res, next) {
  if (req.session && req.session.user) {
    const users = JSON.parse(fs.readFileSync(usersFilePath).toString());
    const userExists = users.some(user => user.username === req.session.user.username);
    if (userExists) {
      next();
    } else {
      req.session.destroy();
      res.redirect('/login.html');
    }
  } else {
    res.redirect('/login.html');
  }
}

// 路由定义
app.get('/', (req, res) => res.redirect('/Register.html'));
app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid'); // 清除session的cookie
    res.redirect('/login.html'); // 重定向到登录页面
  });
});
app.use('/private', requireLogin, express.static('private'));

app.get('/data.html', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'private/data.html'));
});

// 用户注册
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const users = JSON.parse(fs.readFileSync(usersFilePath).toString());

  if (users.some(user => user.username === username)) {
    return res.status(400).send('Username already exists');
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ username, password: hashedPassword });
  fs.writeFileSync(usersFilePath, JSON.stringify(users, null, 2));
  res.redirect('/Login.html');
});

// 用户登录
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const ip = req.ip;
  const currentAttempt = loginAttempts[ip] || { count: 0, unlockTime: new Date() };

  if (new Date() < currentAttempt.unlockTime) {
    const waitTime = Math.round((currentAttempt.unlockTime - new Date()) / 1000);
    return res.status(429).send(`Please wait ${waitTime} seconds before trying again.`);
  }

  const users = JSON.parse(fs.readFileSync(usersFilePath).toString());
  const user = users.find(u => u.username === username);

  if (!user || !(await bcrypt.compare(password, user.password))) {
    handleFailedLoginAttempt(ip, currentAttempt);
    const message = currentAttempt.count >= LOGIN_ATTEMPT_LIMIT ? 
      'Password incorrect. Account locked for 3 minutes.' : 
      `Password incorrect. You have ${LOGIN_ATTEMPT_LIMIT - currentAttempt.count} attempts remaining.`;
    return res.status(401).send(message);
  }

  loginAttempts[ip] = { count: 0, unlockTime: new Date() }; // Reset on successful login
  req.session.user = { username: user.username };
  res.redirect('/data.html');
});

// 辅助函数：处理失败的登录尝试
function handleFailedLoginAttempt(ip, currentAttempt) {
  currentAttempt.count++;
  loginAttempts[ip] = currentAttempt;

  if (currentAttempt.count >= LOGIN_ATTEMPT_LIMIT) {
    currentAttempt.unlockTime = new Date(new Date().getTime() + LOCK_TIME);
  }
}

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
  initializeUsersFile();
});






