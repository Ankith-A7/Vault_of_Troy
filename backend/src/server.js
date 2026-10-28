const app = require('./app');
const config = require('./config');
const server = app.listen(config.PORT, () => console.log(`Aegis Vault API listening on ${config.BASE_URL} (port ${config.PORT})`));
function shutdown() { server.close(() => process.exit(0)); }
process.on('SIGINT',shutdown);
process.on('SIGTERM',shutdown);
