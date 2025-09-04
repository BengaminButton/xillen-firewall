package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var author = "t.me/Bengamin_Button t.me/XillenAdapter"

type FirewallRule struct {
	ID          int       `json:"id"`
	Name        string    `json:"name"`
	Action      string    `json:"action"`
	Protocol    string    `json:"protocol"`
	SourceIP    string    `json:"source_ip"`
	DestIP      string    `json:"dest_ip"`
	SourcePort  int       `json:"source_port"`
	DestPort    int       `json:"dest_port"`
	Direction   string    `json:"direction"`
	Enabled     bool      `json:"enabled"`
	Created     time.Time `json:"created"`
	Description string    `json:"description"`
}

type ConnectionLog struct {
	Timestamp  time.Time `json:"timestamp"`
	SourceIP   string    `json:"source_ip"`
	DestIP     string    `json:"dest_ip"`
	SourcePort int       `json:"source_port"`
	DestPort   int       `json:"dest_port"`
	Protocol   string    `json:"protocol"`
	Action     string    `json:"action"`
	RuleID     int       `json:"rule_id"`
	Bytes      int64     `json:"bytes"`
}

type Firewall struct {
	rules             []FirewallRule
	logs              []ConnectionLog
	mu                sync.RWMutex
	config            Config
	statistics        Statistics
	blockedIPs        map[string]bool
	allowedIPs        map[string]bool
	rateLimits        map[string]int
	activeConnections map[string]time.Time
}

type Config struct {
	LogFile       string `json:"log_file"`
	ConfigFile    string `json:"config_file"`
	MaxLogSize    int64  `json:"max_log_size"`
	LogLevel      string `json:"log_level"`
	AutoBlock     bool   `json:"auto_block"`
	BlockDuration int    `json:"block_duration_minutes"`
	RateLimit     int    `json:"rate_limit_per_minute"`
	EnableLogging bool   `json:"enable_logging"`
	DefaultAction string `json:"default_action"`
}

type Statistics struct {
	PacketsBlocked     int64     `json:"packets_blocked"`
	PacketsAllowed     int64     `json:"packets_allowed"`
	ConnectionsBlocked int64     `json:"connections_blocked"`
	ConnectionsAllowed int64     `json:"connections_allowed"`
	RulesProcessed     int64     `json:"rules_processed"`
	StartTime          time.Time `json:"start_time"`
	LastActivity       time.Time `json:"last_activity"`
	BlockedIPs         int       `json:"blocked_ips"`
	AllowedIPs         int       `json:"allowed_ips"`
}

func NewFirewall() *Firewall {
	return &Firewall{
		rules:             make([]FirewallRule, 0),
		logs:              make([]ConnectionLog, 0),
		blockedIPs:        make(map[string]bool),
		allowedIPs:        make(map[string]bool),
		rateLimits:        make(map[string]int),
		activeConnections: make(map[string]time.Time),
		config: Config{
			LogFile:       "firewall.log",
			ConfigFile:    "firewall_config.json",
			MaxLogSize:    100 * 1024 * 1024,
			LogLevel:      "info",
			AutoBlock:     true,
			BlockDuration: 60,
			RateLimit:     100,
			EnableLogging: true,
			DefaultAction: "deny",
		},
		statistics: Statistics{
			StartTime: time.Now(),
		},
	}
}

func (fw *Firewall) LoadConfig(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &fw.config)
}

func (fw *Firewall) SaveConfig(filename string) error {
	data, err := json.MarshalIndent(fw.config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

func (fw *Firewall) AddRule(rule FirewallRule) {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	rule.ID = len(fw.rules) + 1
	rule.Created = time.Now()
	fw.rules = append(fw.rules, rule)

	fw.log(fmt.Sprintf("Правило добавлено: %s", rule.Name))
}

func (fw *Firewall) RemoveRule(id int) bool {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	for i, rule := range fw.rules {
		if rule.ID == id {
			fw.rules = append(fw.rules[:i], fw.rules[i+1:]...)
			fw.log(fmt.Sprintf("Правило удалено: ID %d", id))
			return true
		}
	}
	return false
}

func (fw *Firewall) EnableRule(id int) bool {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	for i := range fw.rules {
		if fw.rules[i].ID == id {
			fw.rules[i].Enabled = true
			fw.log(fmt.Sprintf("Правило включено: ID %d", id))
			return true
		}
	}
	return false
}

func (fw *Firewall) DisableRule(id int) bool {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	for i := range fw.rules {
		if fw.rules[i].ID == id {
			fw.rules[i].Enabled = false
			fw.log(fmt.Sprintf("Правило отключено: ID %d", id))
			return true
		}
	}
	return false
}

func (fw *Firewall) ProcessPacket(sourceIP, destIP string, sourcePort, destPort int, protocol string) string {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	fw.statistics.LastActivity = time.Now()
	fw.statistics.RulesProcessed++

	connectionKey := fmt.Sprintf("%s:%d->%s:%d", sourceIP, sourcePort, destIP, destPort)

	if fw.isRateLimited(sourceIP) {
		fw.blockIP(sourceIP)
		fw.logConnection(sourceIP, destIP, sourcePort, destPort, protocol, "block", 0, "rate_limit")
		fw.statistics.PacketsBlocked++
		return "block"
	}

	if fw.isBlocked(sourceIP) {
		fw.logConnection(sourceIP, destIP, sourcePort, destPort, protocol, "block", 0, "blocked_ip")
		fw.statistics.PacketsBlocked++
		return "block"
	}

	if fw.isAllowed(sourceIP) {
		fw.logConnection(sourceIP, destIP, sourcePort, destPort, protocol, "allow", 1024, "allowed_ip")
		fw.statistics.PacketsAllowed++
		return "allow"
	}

	for _, rule := range fw.rules {
		if !rule.Enabled {
			continue
		}

		if fw.matchesRule(rule, sourceIP, destIP, sourcePort, destPort, protocol) {
			action := rule.Action
			fw.logConnection(sourceIP, destIP, sourcePort, destPort, protocol, action, 1024, rule.Name)

			if action == "allow" {
				fw.statistics.PacketsAllowed++
			} else {
				fw.statistics.PacketsBlocked++
			}

			return action
		}
	}

	defaultAction := fw.config.DefaultAction
	fw.logConnection(sourceIP, destIP, sourcePort, destPort, protocol, defaultAction, 0, "default")

	if defaultAction == "allow" {
		fw.statistics.PacketsAllowed++
	} else {
		fw.statistics.PacketsBlocked++
	}

	return defaultAction
}

func (fw *Firewall) matchesRule(rule FirewallRule, sourceIP, destIP string, sourcePort, destPort int, protocol string) bool {
	if rule.Protocol != "any" && rule.Protocol != protocol {
		return false
	}

	if rule.SourceIP != "any" && rule.SourceIP != sourceIP {
		return false
	}

	if rule.DestIP != "any" && rule.DestIP != destIP {
		return false
	}

	if rule.SourcePort != 0 && rule.SourcePort != sourcePort {
		return false
	}

	if rule.DestPort != 0 && rule.DestPort != destPort {
		return false
	}

	return true
}

func (fw *Firewall) isBlocked(ip string) bool {
	return fw.blockedIPs[ip]
}

func (fw *Firewall) isAllowed(ip string) bool {
	return fw.allowedIPs[ip]
}

func (fw *Firewall) blockIP(ip string) {
	fw.blockedIPs[ip] = true
	fw.statistics.BlockedIPs = len(fw.blockedIPs)

	if fw.config.AutoBlock {
		go func() {
			time.Sleep(time.Duration(fw.config.BlockDuration) * time.Minute)
			fw.unblockIP(ip)
		}()
	}
}

func (fw *Firewall) unblockIP(ip string) {
	delete(fw.blockedIPs, ip)
	fw.statistics.BlockedIPs = len(fw.blockedIPs)
	fw.log(fmt.Sprintf("IP разблокирован: %s", ip))
}

func (fw *Firewall) allowIP(ip string) {
	fw.allowedIPs[ip] = true
	fw.statistics.AllowedIPs = len(fw.allowedIPs)
	fw.log(fmt.Sprintf("IP добавлен в белый список: %s", ip))
}

func (fw *Firewall) isRateLimited(ip string) bool {
	now := time.Now()
	minute := now.Truncate(time.Minute)
	key := fmt.Sprintf("%s_%d", ip, minute.Unix())

	fw.rateLimits[key]++
	return fw.rateLimits[key] > fw.config.RateLimit
}

func (fw *Firewall) logConnection(sourceIP, destIP string, sourcePort, destPort int, protocol, action string, bytes int64, ruleName string) {
	if !fw.config.EnableLogging {
		return
	}

	log := ConnectionLog{
		Timestamp:  time.Now(),
		SourceIP:   sourceIP,
		DestIP:     destIP,
		SourcePort: sourcePort,
		DestPort:   destPort,
		Protocol:   protocol,
		Action:     action,
		Bytes:      bytes,
	}

	fw.logs = append(fw.logs, log)

	if len(fw.logs) > 10000 {
		fw.logs = fw.logs[1000:]
	}

	fw.log(fmt.Sprintf("%s %s:%d->%s:%d %s %s",
		action, sourceIP, sourcePort, destIP, destPort, protocol, ruleName))
}

func (fw *Firewall) log(message string) {
	if !fw.config.EnableLogging {
		return
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logMessage := fmt.Sprintf("[%s] %s\n", timestamp, message)

	file, err := os.OpenFile(fw.config.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer file.Close()

	file.WriteString(logMessage)
}

func (fw *Firewall) ShowRules() {
	fw.mu.RLock()
	defer fw.mu.RUnlock()

	fmt.Println("\n=== ПРАВИЛА ФАЙРВОЛА ===")
	fmt.Printf("%-4s %-20s %-8s %-8s %-15s %-15s %-8s %-8s %-10s %-8s\n",
		"ID", "Имя", "Действие", "Протокол", "Источник", "Назначение", "Порт1", "Порт2", "Направление", "Статус")
	fmt.Println(strings.Repeat("-", 120))

	for _, rule := range fw.rules {
		status := "Отключен"
		if rule.Enabled {
			status = "Включен"
		}

		fmt.Printf("%-4d %-20s %-8s %-8s %-15s %-15s %-8d %-8d %-10s %-8s\n",
			rule.ID, rule.Name, rule.Action, rule.Protocol, rule.SourceIP, rule.DestIP,
			rule.SourcePort, rule.DestPort, rule.Direction, status)
	}
}

func (fw *Firewall) ShowLogs(limit int) {
	fw.mu.RLock()
	defer fw.mu.RUnlock()

	fmt.Printf("\n=== ЛОГИ ФАЙРВОЛА (последние %d записей) ===\n", limit)
	fmt.Printf("%-20s %-8s %-15s %-15s %-8s %-8s %-8s %-8s\n",
		"Время", "Действие", "Источник", "Назначение", "Порт1", "Порт2", "Протокол", "Правило")
	fmt.Println(strings.Repeat("-", 100))

	start := len(fw.logs) - limit
	if start < 0 {
		start = 0
	}

	for i := start; i < len(fw.logs); i++ {
		log := fw.logs[i]
		fmt.Printf("%-20s %-8s %-15s %-15s %-8d %-8d %-8s %-8s\n",
			log.Timestamp.Format("15:04:05"), log.Action, log.SourceIP, log.DestIP,
			log.SourcePort, log.DestPort, log.Protocol, "N/A")
	}
}

func (fw *Firewall) ShowStatistics() {
	fw.mu.RLock()
	defer fw.mu.RUnlock()

	uptime := time.Since(fw.statistics.StartTime)

	fmt.Println("\n=== СТАТИСТИКА ФАЙРВОЛА ===")
	fmt.Printf("Автор: %s\n", author)
	fmt.Printf("Время работы: %v\n", uptime)
	fmt.Printf("Пакетов заблокировано: %d\n", fw.statistics.PacketsBlocked)
	fmt.Printf("Пакетов разрешено: %d\n", fw.statistics.PacketsAllowed)
	fmt.Printf("Соединений заблокировано: %d\n", fw.statistics.ConnectionsBlocked)
	fmt.Printf("Соединений разрешено: %d\n", fw.statistics.ConnectionsAllowed)
	fmt.Printf("Правил обработано: %d\n", fw.statistics.RulesProcessed)
	fmt.Printf("Заблокированных IP: %d\n", fw.statistics.BlockedIPs)
	fmt.Printf("Разрешенных IP: %d\n", fw.statistics.AllowedIPs)
	fmt.Printf("Активных правил: %d\n", len(fw.rules))
	fmt.Printf("Записей в логе: %d\n", len(fw.logs))
}

func (fw *Firewall) CreateDefaultRules() {
	defaultRules := []FirewallRule{
		{
			Name:        "Разрешить локальный трафик",
			Action:      "allow",
			Protocol:    "any",
			SourceIP:    "127.0.0.1",
			DestIP:      "any",
			Direction:   "inbound",
			Enabled:     true,
			Description: "Разрешить весь локальный трафик",
		},
		{
			Name:        "Блокировать SSH атаки",
			Action:      "block",
			Protocol:    "tcp",
			SourceIP:    "any",
			DestIP:      "any",
			DestPort:    22,
			Direction:   "inbound",
			Enabled:     true,
			Description: "Блокировать попытки подключения к SSH",
		},
		{
			Name:        "Разрешить HTTP/HTTPS",
			Action:      "allow",
			Protocol:    "tcp",
			SourceIP:    "any",
			DestIP:      "any",
			DestPort:    80,
			Direction:   "inbound",
			Enabled:     true,
			Description: "Разрешить HTTP трафик",
		},
		{
			Name:        "Разрешить HTTPS",
			Action:      "allow",
			Protocol:    "tcp",
			SourceIP:    "any",
			DestIP:      "any",
			DestPort:    443,
			Direction:   "inbound",
			Enabled:     true,
			Description: "Разрешить HTTPS трафик",
		},
		{
			Name:        "Блокировать подозрительные IP",
			Action:      "block",
			Protocol:    "any",
			SourceIP:    "any",
			DestIP:      "any",
			Direction:   "inbound",
			Enabled:     true,
			Description: "Блокировать подозрительные соединения",
		},
	}

	for _, rule := range defaultRules {
		fw.AddRule(rule)
	}

	fmt.Println("✅ Созданы правила по умолчанию")
}

func (fw *Firewall) InteractiveMode() {
	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Println("\n🔥 Xillen Firewall")
		fmt.Printf("👨‍💻 Автор: %s\n", author)
		fmt.Println("\nОпции:")
		fmt.Println("1. Показать правила")
		fmt.Println("2. Добавить правило")
		fmt.Println("3. Удалить правило")
		fmt.Println("4. Включить/отключить правило")
		fmt.Println("5. Показать логи")
		fmt.Println("6. Показать статистику")
		fmt.Println("7. Заблокировать IP")
		fmt.Println("8. Разблокировать IP")
		fmt.Println("9. Добавить в белый список")
		fmt.Println("10. Создать правила по умолчанию")
		fmt.Println("11. Настройки")
		fmt.Println("12. Тест пакета")
		fmt.Println("0. Выход")

		fmt.Print("\nВыберите опцию: ")
		scanner.Scan()
		choice := scanner.Text()

		switch choice {
		case "1":
			fw.ShowRules()

		case "2":
			fw.addRuleInteractive(scanner)

		case "3":
			fmt.Print("ID правила для удаления: ")
			scanner.Scan()
			id, _ := strconv.Atoi(scanner.Text())
			if fw.RemoveRule(id) {
				fmt.Println("✅ Правило удалено")
			} else {
				fmt.Println("❌ Правило не найдено")
			}

		case "4":
			fmt.Print("ID правила: ")
			scanner.Scan()
			id, _ := strconv.Atoi(scanner.Text())
			fmt.Print("Включить (1) или отключить (0): ")
			scanner.Scan()
			enable, _ := strconv.Atoi(scanner.Text())

			if enable == 1 {
				if fw.EnableRule(id) {
					fmt.Println("✅ Правило включено")
				} else {
					fmt.Println("❌ Правило не найдено")
				}
			} else {
				if fw.DisableRule(id) {
					fmt.Println("✅ Правило отключено")
				} else {
					fmt.Println("❌ Правило не найдено")
				}
			}

		case "5":
			fmt.Print("Количество записей (по умолчанию 50): ")
			scanner.Scan()
			limitStr := scanner.Text()
			limit := 50
			if limitStr != "" {
				limit, _ = strconv.Atoi(limitStr)
			}
			fw.ShowLogs(limit)

		case "6":
			fw.ShowStatistics()

		case "7":
			fmt.Print("IP для блокировки: ")
			scanner.Scan()
			ip := scanner.Text()
			fw.blockIP(ip)
			fmt.Printf("✅ IP %s заблокирован\n", ip)

		case "8":
			fmt.Print("IP для разблокировки: ")
			scanner.Scan()
			ip := scanner.Text()
			fw.unblockIP(ip)
			fmt.Printf("✅ IP %s разблокирован\n", ip)

		case "9":
			fmt.Print("IP для добавления в белый список: ")
			scanner.Scan()
			ip := scanner.Text()
			fw.allowIP(ip)
			fmt.Printf("✅ IP %s добавлен в белый список\n", ip)

		case "10":
			fw.CreateDefaultRules()

		case "11":
			fw.showSettings(scanner)

		case "12":
			fw.testPacket(scanner)

		case "0":
			fmt.Println("👋 До свидания!")
			return

		default:
			fmt.Println("❌ Неверный выбор")
		}
	}
}

func (fw *Firewall) addRuleInteractive(scanner *bufio.Scanner) {
	fmt.Print("Имя правила: ")
	scanner.Scan()
	name := scanner.Text()

	fmt.Print("Действие (allow/block): ")
	scanner.Scan()
	action := scanner.Text()

	fmt.Print("Протокол (tcp/udp/any): ")
	scanner.Scan()
	protocol := scanner.Text()

	fmt.Print("IP источника (any для всех): ")
	scanner.Scan()
	sourceIP := scanner.Text()

	fmt.Print("IP назначения (any для всех): ")
	scanner.Scan()
	destIP := scanner.Text()

	fmt.Print("Порт источника (0 для любого): ")
	scanner.Scan()
	sourcePortStr := scanner.Text()
	sourcePort, _ := strconv.Atoi(sourcePortStr)

	fmt.Print("Порт назначения (0 для любого): ")
	scanner.Scan()
	destPortStr := scanner.Text()
	destPort, _ := strconv.Atoi(destPortStr)

	fmt.Print("Направление (inbound/outbound/any): ")
	scanner.Scan()
	direction := scanner.Text()

	fmt.Print("Описание: ")
	scanner.Scan()
	description := scanner.Text()

	rule := FirewallRule{
		Name:        name,
		Action:      action,
		Protocol:    protocol,
		SourceIP:    sourceIP,
		DestIP:      destIP,
		SourcePort:  sourcePort,
		DestPort:    destPort,
		Direction:   direction,
		Enabled:     true,
		Description: description,
	}

	fw.AddRule(rule)
	fmt.Println("✅ Правило добавлено")
}

func (fw *Firewall) showSettings(scanner *bufio.Scanner) {
	fmt.Printf("\n=== НАСТРОЙКИ ===\n")
	fmt.Printf("Файл логов: %s\n", fw.config.LogFile)
	fmt.Printf("Уровень логирования: %s\n", fw.config.LogLevel)
	fmt.Printf("Автоблокировка: %t\n", fw.config.AutoBlock)
	fmt.Printf("Время блокировки: %d мин\n", fw.config.BlockDuration)
	fmt.Printf("Лимит запросов: %d/мин\n", fw.config.RateLimit)
	fmt.Printf("Логирование: %t\n", fw.config.EnableLogging)
	fmt.Printf("Действие по умолчанию: %s\n", fw.config.DefaultAction)
}

func (fw *Firewall) testPacket(scanner *bufio.Scanner) {
	fmt.Print("IP источника: ")
	scanner.Scan()
	sourceIP := scanner.Text()

	fmt.Print("IP назначения: ")
	scanner.Scan()
	destIP := scanner.Text()

	fmt.Print("Порт источника: ")
	scanner.Scan()
	sourcePortStr := scanner.Text()
	sourcePort, _ := strconv.Atoi(sourcePortStr)

	fmt.Print("Порт назначения: ")
	scanner.Scan()
	destPortStr := scanner.Text()
	destPort, _ := strconv.Atoi(destPortStr)

	fmt.Print("Протокол: ")
	scanner.Scan()
	protocol := scanner.Text()

	action := fw.ProcessPacket(sourceIP, destIP, sourcePort, destPort, protocol)
	fmt.Printf("Результат: %s\n", action)
}

func main() {
	fmt.Println(author)

	firewall := NewFirewall()
	firewall.CreateDefaultRules()

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "config":
			if len(os.Args) > 2 {
				firewall.LoadConfig(os.Args[2])
			}
		case "test":
			if len(os.Args) > 6 {
				sourceIP := os.Args[2]
				destIP := os.Args[3]
				sourcePort, _ := strconv.Atoi(os.Args[4])
				destPort, _ := strconv.Atoi(os.Args[5])
				protocol := os.Args[6]

				action := firewall.ProcessPacket(sourceIP, destIP, sourcePort, destPort, protocol)
				fmt.Printf("Результат: %s\n", action)
				return
			}
		}
	}

	firewall.InteractiveMode()
}
