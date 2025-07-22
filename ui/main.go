package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// 配置结构体
type Config struct {
	HistoryPath   string `json:"history_path"`
	DefaultLimit  int    `json:"default_limit"`
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

// 全局配置
var config Config

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
			searchLower := strings.ToLower(search)
			filtered := make([]string, 0)
			for _, cmd := range history {
				if strings.Contains(strings.ToLower(cmd), searchLower) {
					filtered = append(filtered, cmd)
				}
			}
			history = filtered
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

	// 设置路由
	http.HandleFunc("/", handleHome)

	// 启动服务器
	addr := fmt.Sprintf(":%d", 8080)
	log.Printf("服务器运行在 http://localhost:%d", 8080)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("服务器启动失败: %v", err)
	}
}
