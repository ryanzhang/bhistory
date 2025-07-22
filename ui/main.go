package main

import (
	"context"
    "crypto/tls"
    "crypto/x509"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
	"regexp"
	"time"
    "github.com/coreos/go-oidc"
    "golang.org/x/oauth2"

)

// 配置结构体
type Config struct {
    HistoryPath      string `json:"history_path"`
    DefaultLimit     int    `json:"default_limit"`
    KeycloakURL      string `json:"keycloak_url"`
    RedirectURL      string `json:"redirect_url"`
    KeycloakCertPath string `json:"keycloak_cert_path"`
}

// 页面数据结构体
type PageData struct {
	History      []string
	Search       string
	Error        string
	LineCount    int
	LineInPage    int
	LimitInPage   int
	LastModified string
}

var (
	config       Config
	oauth2Config oauth2.Config // OAuth2 配置
	verifier     *oidc.IDTokenVerifier
)

// 读取配置文件
func loadConfig() error {
	data, err := os.ReadFile("config.json")
	if err != nil {
		return fmt.Errorf("无法读取 config.json: %v", err)
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("解析 config.json 失败: %v", err)
	}
	if config.DefaultLimit <= 0 {
		config.DefaultLimit = 100 // 默认值
	}
    if config.KeycloakURL == "" {
        config.KeycloakURL = "https://keycloak.gce:8443/realms/bhistory"
    }
    if config.RedirectURL == "" {
        config.RedirectURL = "https://localhost:8080/callback"
    }
    if config.KeycloakCertPath == "" {
        config.KeycloakCertPath = "./keycloak.crt"
    }
	return nil
}

// 读取 bash_history 文件
func readHistory() ([]string, time.Time, error) {
	fileInfo, err := os.Stat(config.HistoryPath)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("无法获取文件信息: %v", err)
	}
	data, err := os.ReadFile(config.HistoryPath)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("无法读取 bash_history: %v", err)
	}

	// 按行分割并去重
	lines := strings.Split(string(data), "\n")
	uniqueLines := make([]string, 0)
	seen := make(map[string]struct{})
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			if _, exists := seen[line]; !exists {
				seen[line] = struct{}{}
				uniqueLines = append(uniqueLines, line)
			}
		}
	}
	return uniqueLines, fileInfo.ModTime(), nil
}

// 搜索过滤函数，支持正则表达式
func filterHistory(history []string, search string) ([]string, error) {
	if search == "" {
		return history, nil
	}

	// 转义用户输入，防止正则表达式注入
	searchPattern := regexp.QuoteMeta(search)
	// 还原用户明确输入的 ^ 和 $，以支持正则表达式
	if strings.Contains(searchPattern, "\\^") || strings.Contains(searchPattern, "\\$") {
		searchPattern = strings.ReplaceAll(searchPattern, "\\^", "^")
		searchPattern = strings.ReplaceAll(searchPattern, "\\$", "$")
	}

	// 编译正则表达式，忽略大小写
	re, err := regexp.Compile("(?i)" + searchPattern)
	if err != nil {
		return nil, fmt.Errorf("无效的正则表达式: %v", err)
	}

	// 过滤历史记录
	filtered := make([]string, 0)
	for _, cmd := range history {
		if re.MatchString(cmd) {
			filtered = append(filtered, cmd)
		}
	}
	return filtered, nil
}

// authMiddleware 检查用户是否认证，未认证则重定向到 Keycloak 登录页面
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// // 从请求头获取 Authorization: Bearer <token>
		// authHeader := r.Header.Get("Authorization")
		// if authHeader == "" {
		// 	// 未提供令牌，重定向到 Keycloak 登录页面
		// 	http.Redirect(w, r, oauth2Config.AuthCodeURL("random-state"), http.StatusFound)
		// 	return
		// }

		// // 提取 Bearer 令牌
		// parts := strings.Split(authHeader, " ")
		// if len(parts) != 2 || parts[0] != "Bearer" {
		// 	log.Printf("无效的 Authorization 头: %s", authHeader)
		// 	http.Redirect(w, r, oauth2Config.AuthCodeURL("random-state"), http.StatusFound)
		// 	return
		// }

		// 验证 ID 令牌
		// _, err := verifier.Verify(context.Background(), parts[1])

		// 从 Cookie 验证
		cookie, err := r.Cookie("id_token")
		if err != nil || cookie.Value == "" {
			log.Printf("未找到 id_token Cookie: %v", err)
			http.Redirect(w, r, oauth2Config.AuthCodeURL("random-state"), http.StatusFound)
			return
		}
		_, err = verifier.Verify(context.Background(), cookie.Value)
		if err != nil {
			log.Printf("令牌验证失败: %v", err)
			http.Redirect(w, r, oauth2Config.AuthCodeURL("random-state"), http.StatusFound)
			return
		}

		// 令牌有效，继续处理请求
		next(w, r)
	}
}

// handleLogin 触发 Keycloak 登录
func handleLogin(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, oauth2Config.AuthCodeURL("random-state"), http.StatusFound)
}

// handleCallback 处理 Keycloak 回调，验证令牌后重定向到主页
func handleCallback(w http.ResponseWriter, r *http.Request) {
    // 创建自定义 HTTP 客户端，加载 Keycloak 证书
    caCert, err := os.ReadFile("keycloak.crt")
    if err != nil {
        log.Printf("无法读取 Keycloak 证书: %v", err)
        http.Error(w, "服务器配置错误", http.StatusInternalServerError)
        return
    }
    caCertPool := x509.NewCertPool()
    if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
        log.Printf("无法解析 Keycloak 证书")
        http.Error(w, "服务器配置错误", http.StatusInternalServerError)
        return
    }
    tr := &http.Transport{
        TLSClientConfig: &tls.Config{
            RootCAs: caCertPool,
        },
    }
    client := &http.Client{Transport: tr}
    ctx := context.WithValue(context.Background(), oauth2.HTTPClient, client)

    if r.URL.Query().Get("state") != "random-state" {
        log.Printf("state 参数不匹配: got %s, expected random-state", r.URL.Query().Get("state"))
        http.Error(w, "state 参数不匹配", http.StatusBadRequest)
        return
    }
    oauth2Token, err := oauth2Config.Exchange(ctx, r.URL.Query().Get("code"))
    if err != nil {
        if oauthErr, ok := err.(*oauth2.RetrieveError); ok {
            log.Printf("交换令牌失败: %v, Response: %s", err, oauthErr.Body)
        } else {
            log.Printf("交换令牌失败: %v", err)
        }
        http.Error(w, "无法获取令牌", http.StatusInternalServerError)
        return
    }
    rawIDToken, ok := oauth2Token.Extra("id_token").(string)
    if !ok {
        log.Printf("令牌中缺少 id_token")
        http.Error(w, "令牌中缺少 id_token", http.StatusInternalServerError)
        return
    }
    _, err = verifier.Verify(context.Background(), rawIDToken)
    if err != nil {
        log.Printf("ID 令牌验证失败: %v", err)
        http.Error(w, "无效的 ID 令牌", http.StatusInternalServerError)
        return
    }
	// handleCallback 中存储 id_token 到 Cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "id_token",
		Value:    rawIDToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // 开发环境设为 false，生产环境设为 true
		MaxAge:   3600,  // 与 Keycloak 令牌有效期同步
	})

    http.Redirect(w, r, "/", http.StatusFound)
}

// 处理主页请求
func handleHome(w http.ResponseWriter, r *http.Request) {
	// 解析查询参数
	search := r.URL.Query().Get("search")
	data := PageData{Search: search}

	// 读取历史记录
	history, modTime, err := readHistory()
	if err != nil {
		data.Error = fmt.Sprintf("无法读取命令历史: %v", err)
	} else {
		// 应用搜索过滤
		if search != "" {
			filtered, err := filterHistory(history, search)
			if err != nil {
				data.Error = err.Error()
			} else {
				history = filtered
				if len(history) == 0 {
					data.Error = "没有匹配的命令"
				}
			}
		}

		data.LineCount = len(history)
		// 限制显示行数
		limit := config.DefaultLimit
		if len(history) > limit {
			history = history[:limit]
		}

		data.History = history
		data.LineInPage = len(history)
		data.LimitInPage = config.DefaultLimit
		data.LastModified = modTime.Format("2006-01-02 15:04:05")
	}

	// 渲染模板
	tmpl, err := template.ParseFiles("templates/index.html")
	if err != nil {
		http.Error(w, "模板加载失败", http.StatusInternalServerError)
		return
	}
	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, "模板渲染失败", http.StatusInternalServerError)
		return
	}
}

func main() {
	// 加载配置文件
	if err := loadConfig(); err != nil {
		log.Fatalf("加载配置文件失败: %v", err)
	}

    // 加载 Keycloak 的 TLS 证书
    caCert, err := os.ReadFile("keycloak.crt")
    if err != nil {
        log.Fatalf("无法读取 Keycloak 证书: %v", err)
    }
    caCertPool := x509.NewCertPool()
    if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
        log.Fatalf("无法解析 Keycloak 证书")
    }

    // 创建自定义 HTTP 客户端，使用 Keycloak 的证书
    tr := &http.Transport{
        TLSClientConfig: &tls.Config{
            RootCAs: caCertPool,
        },
    }
    client := &http.Client{Transport: tr}
    ctx := oidc.ClientContext(context.Background(), client)

	//authentication logic
	// configURL := "https://keycloak.gce:8443/realms/bhistory"

	// 初始化 OIDC 提供者
    provider, err := oidc.NewProvider(ctx, config.KeycloakURL)
    if err != nil {
		log.Fatalf("初始化 Keycloak provider 失败: %v", err)
    }

	clientID := os.Getenv("KEYCLOAK_CLIENT_ID")
	clientSecret := os.Getenv("KEYCLOAK_CLIENT_SECRET")


    // redirectURL := "http://localhost:8080/callback"
    // Configure an OpenID Connect aware OAuth2 client.
    oauth2Config = oauth2.Config{
        ClientID:     clientID,
        ClientSecret: clientSecret,
        RedirectURL:  config.RedirectURL,
        // Discovery returns the OAuth2 endpoints.
        Endpoint: provider.Endpoint(),
        // "openid" is a required scope for OpenID Connect flows.
        Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
    }

    // oauth2Config.tr= tr // 使用相同的 Transport 确保令牌交换忽略 TLS 错误
    log.Printf("oauth2Config: ClientID=%s, ClientSecret=%s, RedirectURL=%s, TokenURL=%s",
        oauth2Config.ClientID, oauth2Config.ClientSecret, oauth2Config.RedirectURL, oauth2Config.Endpoint.TokenURL)


    oidcConfig := &oidc.Config{
        ClientID: clientID,
    }

    verifier = provider.Verifier(oidcConfig)

    http.HandleFunc("/login", handleLogin)

    http.HandleFunc("/callback", handleCallback)

	// 设置路由
	http.HandleFunc("/", authMiddleware(handleHome))

	// 启动服务器
	addr := fmt.Sprintf("0.0.0.0:%d", 8080)
	log.Printf("服务器运行在 http://0.0.0.0:%d", 8080)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("服务器启动失败: %v", err)
	}
}
