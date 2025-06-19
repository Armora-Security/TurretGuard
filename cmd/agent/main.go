package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/shirou/gopsutil/cpu" // For CPU usage
	"github.com/shirou/gopsutil/mem" // For Memory usage
)

// Define Prometheus metrics
var (
	cpuUsage = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "turretguard_cpu_percent_total",
		Help: "Current CPU usage percentage.",
	})
	memTotal = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "turretguard_memory_bytes_total",
		Help: "Total system memory in bytes.",
	})
	memUsed = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "turretguard_memory_bytes_used",
		Help: "Used system memory in bytes.",
	})
	securityEventCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "turretguard_security_events_total",
		Help: "Total count of security events by type.",
	}, []string{"event_type", "severity"})
)

// Function to collect metrics
func collectMetrics() {
	for {
		// CPU Usage
		percentages, err := cpu.Percent(time.Second, false) // cpu.Percent returns average for all CPUs
		if err == nil && len(percentages) > 0 {
			cpuUsage.Set(percentages[0])
		} else if err != nil {
			log.Printf("ERROR: Could not collect CPU metrics: %v", err)
		}

		// Memory Usage
		vmem, err := mem.VirtualMemory()
		if err == nil {
			memTotal.Set(float64(vmem.Total))
			memUsed.Set(float64(vmem.Used))
		} else {
			log.Printf("ERROR: Could not collect Memory metrics: %v", err)
		}

		time.Sleep(5 * time.Second) // Collect every 5 seconds
	}
}

// Function to simulate logging security events
func simulateSecurityEvents() {
	logFile, err := os.OpenFile("/var/log/turretguard/security_events.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("ERROR: Failed to open security log file: %v", err)
	}
	defer logFile.Close()

	securityLogger := log.New(logFile, "TURRETGUARD_SEC: ", log.LstdFlags)

	events := []struct {
		Type    string
		Severity string
		Message string
	}{
		{"Login_Attempt", "INFO", "User 'gila_user' tried to log in from 192.168.1.100"},
		{"Failed_SSH_Login", "WARNING", "Repeated failed SSH login from 203.0.113.42"},
		{"Unauthorized_Access", "CRITICAL", "Attempted access to /admin endpoint by unknown IP 10.0.0.5"},
		{"File_Modification", "INFO", "/etc/passwd modified by 'root'"},
	}

	for {
		// Simulate a security event randomly
		event := events[time.Now().UnixNano()%int64(len(events))]
		securityLogger.Printf("[%s][%s] %s\n", event.Type, event.Severity, event.Message)

		// Increment Prometheus counter for security events
		securityEventCounter.With(prometheus.Labels{"event_type": event.Type, "severity": event.Severity}).Inc()

		time.Sleep(10 * time.Second) // Log an event every 10 seconds
	}
}

func main() {
	log.Println("Armora TurretGuard Agent starting... Initiating surveillance mode! 🛡️")

	// Create log directory if it doesn't exist
	if _, err := os.Stat("/var/log/turretguard"); os.IsNotExist(err) {
		err = os.MkdirAll("/var/log/turretguard", 0755)
		if err != nil {
			log.Fatalf("Failed to create log directory: %v", err)
		}
	}

	// Start metric collection in a goroutine
	go collectMetrics()

	// Start security event simulation in a goroutine
	go simulateSecurityEvents()

	// Expose Prometheus metrics on /metrics endpoint
	http.Handle("/metrics", promhttp.Handler())
	listenAddr := ":9091" // Agent will listen on port 9091
	log.Printf("Serving TurretGuard metrics on %s/metrics. Get ready for data fireworks! 🎆", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}
