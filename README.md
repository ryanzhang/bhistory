# Build UI
```
cd ui
make build
ui/bin/bhistory-ui-darwin
```

# 部署到服务器
```
scp ui/bin/bhistory-ui-linux root@xxx:xxx/bhistory/
scp -r ui/templates/ root@xxx:xxx/bhistory/
scp ui/keycloak.crt root@xxx:xxx/bhistory/
scp ui/config.json root@xxx:xxx/bhistory/
```
