// Оболочка Electron: запускает тот же локальный сервер внутри приложения и показывает его в окне.
//   npm run app    — запустить из исходников
//   npm run dist   — собрать exe (папка dist/)
require('./dh-groups');
const { app, BrowserWindow, Menu, dialog, shell } = require('electron');
const path = require('path');

// Порт постоянный: от адреса страницы зависит, где браузер хранит тему и последний открытый коммутатор
const PORT = +process.env.SWCFG_PORT || 18080;

if (!app.requestSingleInstanceLock()) app.quit();

// Данные — в профиле пользователя (%APPDATA%\switchConfig\data), а не внутри exe.
// Пароли зашифрованы для текущей учётной записи Windows, так что папку можно переносить только в пределах неё.
process.env.SWCFG_DATA = process.env.SWCFG_DATA || path.join(app.getPath('userData'), 'data');

let win = null;
let baseUrl = null;

function isLocal(url) { return baseUrl && url.startsWith(baseUrl); }
function openInBrowser(url) { if (/^https?:/.test(url)) shell.openExternal(url); }

function createWindow() {
  win = new BrowserWindow({
    width: 1400, height: 900, minWidth: 900, minHeight: 600,
    title: 'Конфигурации коммутаторов',
    autoHideMenuBar: true,
    icon: path.join(__dirname, '..', 'build', 'icon.png'),
    webPreferences: { contextIsolation: true, nodeIntegration: false, sandbox: true },
  });
  win.removeMenu();

  // Свои страницы открываем в окне приложения, внешние ссылки — в обычном браузере
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (isLocal(url)) return { action: 'allow', overrideBrowserWindowOptions: { autoHideMenuBar: true } };
    openInBrowser(url);
    return { action: 'deny' };
  });
  win.webContents.on('will-navigate', (e, url) => {
    if (!isLocal(url)) { e.preventDefault(); openInBrowser(url); }
  });

  // F5 — обновить, F12 — инструменты разработчика, Ctrl+колесо/±/0 — масштаб
  win.webContents.on('before-input-event', (e, input) => {
    if (input.type !== 'keyDown') return;
    if (input.key === 'F5') win.webContents.reload();
    else if (input.key === 'F12') win.webContents.toggleDevTools();
  });

  win.on('closed', () => { win = null; });
  win.loadURL(baseUrl);
}

app.on('second-instance', () => {
  if (!win) return;
  if (win.isMinimized()) win.restore();
  win.focus();
});

app.whenReady().then(async () => {
  Menu.setApplicationMenu(null);
  try {
    baseUrl = await require('../server/server').start(PORT);
  } catch (err) {
    dialog.showErrorBox('Не удалось запустить',
      err.code === 'EADDRINUSE'
        ? `Порт ${PORT} занят другой программой. Закройте её или задайте другой порт в переменной окружения SWCFG_PORT.`
        : String(err && err.stack || err));
    app.exit(1);
    return;
  }
  createWindow();
});

app.on('window-all-closed', () => app.quit());
