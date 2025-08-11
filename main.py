# Advanced Network Monitor - PySide6 with i18n + Theme Toggle + Security Score + Enhanced Features
# Developed by: Haider Kareem (حيدر كريم)
# Version: 2.0 Enhanced
# Requires: pip install psutil PySide6 jsonschema

import os
import sys
import time
import json
import ctypes
import ipaddress
import subprocess
import logging
import asyncio
from datetime import datetime
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from collections import OrderedDict
from logging.handlers import RotatingFileHandler

import psutil
from PySide6.QtCore import (
    Qt, QAbstractTableModel, QModelIndex, QTimer, QThread, Signal, QObject,
    QSortFilterProxyModel, QRegularExpression, QLocale
)
from PySide6.QtGui import QAction, QPalette, QColor
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTableView,
    QLineEdit, QComboBox, QFileDialog, QSpinBox, QToolBar, QStatusBar, QMessageBox, QStyleFactory,
    QHeaderView, QMenu, QDialog, QFormLayout, QCheckBox
)

# Validation
try:
    import jsonschema
    from jsonschema import validate

    JSONSCHEMA_AVAILABLE = True
except ImportError:
    JSONSCHEMA_AVAILABLE = False


# ==========================
# Enhanced Logging System
# ==========================

def setup_logging() -> logging.Logger:
    """Setup comprehensive logging system with rotation"""
    logger = logging.getLogger('NetworkMonitor')
    logger.setLevel(logging.INFO)

    # Clear existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    # File handler with rotation
    try:
        log_path = os.path.join(os.path.dirname(__file__), 'logs')
        os.makedirs(log_path, exist_ok=True)

        file_handler = RotatingFileHandler(
            os.path.join(log_path, 'network_monitor.log'),
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5,
            encoding='utf-8'
        )

        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        # Console handler for development
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.WARNING)
        console_formatter = logging.Formatter('%(levelname)s - %(message)s')
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)

    except Exception as e:
        print(f"Failed to setup file logging: {e}")
        # Fallback to console only
        console_handler = logging.StreamHandler()
        formatter = logging.Formatter('%(levelname)s - %(message)s')
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    return logger


# Initialize logger
logger = setup_logging()

# ==========================
# Configuration Validation
# ==========================

CONFIG_SCHEMA = {
    "type": "object",
    "properties": {
        "interval_ms": {"type": "integer", "minimum": 200, "maximum": 60000},
        "lang": {"type": "string", "enum": ["en", "ar", "ru"]},
        "theme": {"type": "string", "enum": ["dark", "light"]},
        "only_established": {"type": "boolean"},
        "autostart": {"type": "boolean"}
    },
    "required": ["interval_ms", "lang", "theme"]
}


def validate_config(config: dict) -> bool:
    """Validate configuration against schema"""
    if not JSONSCHEMA_AVAILABLE:
        logger.warning("jsonschema not available, skipping validation")
        return True

    try:
        validate(instance=config, schema=CONFIG_SCHEMA)
        logger.info("Configuration validation passed")
        return True
    except jsonschema.ValidationError as e:
        logger.error(f"Invalid configuration: {e}")
        return False
    except Exception as e:
        logger.error(f"Configuration validation error: {e}")
        return False


# ==========================
# Enhanced Cache with TTL
# ==========================

class LRUCacheWithTTL:
    """LRU Cache with Time-To-Live and size limits"""

    def __init__(self, max_size: int = 100, ttl: float = 300):
        self.cache = OrderedDict()
        self.max_size = max_size
        self.ttl = ttl
        logger.debug(f"Initialized LRU cache: max_size={max_size}, ttl={ttl}s")

    def get(self, key: str) -> Optional[bool]:
        """Get value from cache, return None if expired or not found"""
        if key in self.cache:
            value, timestamp = self.cache[key]
            if time.time() - timestamp < self.ttl:
                # Move to end (most recently used)
                self.cache.move_to_end(key)
                return value
            else:
                # Expired, remove
                del self.cache[key]
                logger.debug(f"Cache entry expired: {key}")
        return None

    def set(self, key: str, value: bool) -> None:
        """Set value in cache with current timestamp"""
        # Remove oldest entries if at capacity
        while len(self.cache) >= self.max_size:
            oldest_key = next(iter(self.cache))
            del self.cache[oldest_key]
            logger.debug(f"Cache evicted oldest entry: {oldest_key}")

        self.cache[key] = (value, time.time())
        logger.debug(f"Cache stored: {key} = {value}")

    def clear(self) -> None:
        """Clear all cache entries"""
        self.cache.clear()
        logger.debug("Cache cleared")

    def stats(self) -> dict:
        """Get cache statistics"""
        return {
            "size": len(self.cache),
            "max_size": self.max_size,
            "ttl": self.ttl
        }


# ==========================
# Enhanced Utilities
# ==========================

def is_admin() -> bool:
    """Check if running with administrator privileges"""
    try:
        if os.name != "nt":
            return os.geteuid() == 0
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception as e:
        logger.error(f"Failed to check admin status: {e}")
        return False


def run_powershell(cmd: str, timeout: float = 3.0) -> Tuple[int, str, str]:
    """Enhanced PowerShell execution with better error handling"""
    if os.name != "nt":
        return (1, "", "PowerShell not available on this platform")

    full_cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd]

    try:
        logger.debug(f"Executing PowerShell command: {cmd}")
        process = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW  # Hide window
        )
        logger.debug(f"PowerShell result: code={process.returncode}")
        return (process.returncode, process.stdout.strip(), process.stderr.strip())

    except subprocess.TimeoutExpired:
        logger.warning(f"PowerShell command timeout: {cmd}")
        return (1, "", "Command timeout")
    except subprocess.CalledProcessError as e:
        logger.error(f"PowerShell command failed: {e}")
        return (e.returncode, "", f"Command failed: {e}")
    except FileNotFoundError:
        logger.error("PowerShell executable not found")
        return (1, "", "PowerShell not found")
    except Exception as e:
        logger.error(f"Unexpected error in PowerShell execution: {e}")
        return (1, "", f"Unexpected error: {type(e).__name__}")


def is_private_ip(ip: str) -> bool:
    """Check if IP address is private"""
    try:
        return ipaddress.ip_address(ip).is_private
    except (ValueError, ipaddress.AddressValueError) as e:
        logger.debug(f"Invalid IP address format: {ip} - {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error checking IP: {e}")
        return False


# ==========================
# i18n (unchanged)
# ==========================

I18N: Dict[str, Dict[str, str]] = {
    'en': {
        'app_title': "I See You — Advanced Network Monitor | Developed by Haider Kareem",
        'start': "Start",
        'stop': "Stop",
        'export_csv': "Export CSV",
        'settings': "Settings",
        'quit': "Quit",
        'search': "Search:",
        'filter_placeholder': "Filter (regex) — process, path, ip, status...",
        'level': "Level:",
        'admin_tip': "⚠️ Run as Admin for best results",
        'admin_ok': "✓ Running as Admin",
        'ready': "Ready",
        'monitoring': "Monitoring...",
        'stopped': "Stopped",
        'copy_row': "Copy row",
        'open_path': "Open file location",
        'terminate': "Terminate process",
        'ask_terminate': "Terminate process {proc} (PID {pid})?",
        'export_title': "Export CSV",
        'export_filter': "CSV files (*.csv)",
        'export_done': "Exported to {path}",
        'export_fail': "Failed: {err}",
        'row_copied': "Row copied to clipboard",
        'only_est': "Show only ESTABLISHED/SYN*",
        'autostart': "Start monitoring on launch",
        'update_interval': "Update interval (ms)",
        'ok': "OK",
        'cancel': "Cancel",
        'open_info': "File path not available.",
        'error': "Error: {msg}",
        'theme': "Theme:",
        'dark': "Dark",
        'light': "Light",
        'language': "Language:",
        'all': "All",
        'safe': "Safe",
        'medium': "Medium",
        'risk': "Risk",
        'columns': "Process,PID,Path,Local,Remote,Status,Time,Security,Level",
        'about': "About",
        'about_title': "About I See You",
        'about_text': """I See You - Advanced Network Monitor v2.0

Developed by: Haider Kareem (حيدر كريم)

Advanced network monitoring tool with security assessment,
multi-language support, and enhanced performance.

Features:
• Real-time network connection monitoring
• Security risk assessment
• Multi-language support (EN/AR/RU)
• Dark/Light themes
• CSV export capabilities
• Advanced filtering and search

© 2025 Haider Kareem. All rights reserved.""",
    },
    'ar': {
        'app_title': "I See You — مراقب الشبكة المتقدم | طوّر من قبل حيدر كريم",
        'start': "بدء",
        'stop': "إيقاف",
        'export_csv': "تصدير CSV",
        'settings': "الإعدادات",
        'quit': "خروج",
        'search': "بحث:",
        'filter_placeholder': "فلترة (Regex) — عملية، مسار، IP، حالة...",
        'level': "المستوى:",
        'admin_tip': "⚠️ يُفضّل التشغيل كمسؤول لنتائج أدق",
        'admin_ok': "✓ يعمل كمسؤول",
        'ready': "جاهز",
        'monitoring': "يراقب...",
        'stopped': "متوقف",
        'copy_row': "نسخ الصف",
        'open_path': "فتح موقع الملف",
        'terminate': "إنهاء العملية",
        'ask_terminate': "إنهاء العملية {proc} (المعرّف {pid})؟",
        'export_title': "تصدير CSV",
        'export_filter': "ملفات CSV (*.csv)",
        'export_done': "تم التصدير إلى {path}",
        'export_fail': "فشل: {err}",
        'row_copied': "تم نسخ الصف",
        'only_est': "عرض ESTABLISHED/SYN* فقط",
        'autostart': "بدء المراقبة عند التشغيل",
        'update_interval': "فترة التحديث (مللي ثانية)",
        'ok': "موافق",
        'cancel': "إلغاء",
        'open_info': "مسار الملف غير متاح.",
        'error': "خطأ: {msg}",
        'theme': "المظهر:",
        'dark': "ليلي",
        'light': "نهاري",
        'language': "اللغة:",
        'all': "الكل",
        'safe': "آمن",
        'medium': "متوسط",
        'risk': "خطر",
        'columns': "العملية,PID,المسار,محلي,بعيد,الحالة,الوقت,الأمان,المستوى",
        'about': "حول",
        'about_title': "حول I See You",
        'about_text': """I See You - مراقب الشبكة المتقدم الإصدار 2.0

طوّر من قبل: حيدر كريم

أداة مراقبة شبكة متقدمة مع تقييم أمني،
دعم متعدد اللغات، وأداء محسّن.

الميزات:
• مراقبة اتصالات الشبكة بالوقت الفعلي
• تقييم المخاطر الأمنية
• دعم متعدد اللغات (EN/AR/RU)
• مظاهر فاتحة/غامقة
• إمكانيات تصدير CSV
• فلترة وبحث متقدم

© 2025 حيدر كريم. جميع الحقوق محفوظة.""",
    },
    'ru': {
        'app_title': "I See You — продвинутый монитор сети | Разработчик: Хайдер Карим",
        'start': "Старт",
        'stop': "Стоп",
        'export_csv': "Экспорт CSV",
        'settings': "Настройки",
        'quit': "Выход",
        'search': "Поиск:",
        'filter_placeholder': "Фильтр (regex) — процесс, путь, ip, статус...",
        'level': "Уровень:",
        'admin_tip': "⚠️ Запустите от имени администратора для лучших результатов",
        'admin_ok': "✓ Запущено с правами администратора",
        'ready': "Готово",
        'monitoring': "Мониторинг...",
        'stopped': "Остановлено",
        'copy_row': "Копировать строку",
        'open_path': "Открыть расположение файла",
        'terminate': "Завершить процесс",
        'ask_terminate': "Завершить процесс {proc} (PID {pid})?",
        'export_title': "Экспорт CSV",
        'export_filter': "Файлы CSV (*.csv)",
        'export_done': "Экспортировано в {path}",
        'export_fail': "Ошибка: {err}",
        'row_copied': "Строка скопирована",
        'only_est': "Показывать только ESTABLISHED/SYN*",
        'autostart': "Запуск мониторинга при старте",
        'update_interval': "Интервал обновления (мс)",
        'ok': "ОК",
        'cancel': "Отмена",
        'open_info': "Путь к файлу недоступен.",
        'error': "Ошибка: {msg}",
        'theme': "Тема:",
        'dark': "Тёмная",
        'light': "Светлая",
        'language': "Язык:",
        'all': "Все",
        'safe': "Безопасно",
        'medium': "Средний",
        'risk': "Риск",
        'columns': "Процесс,PID,Путь,Локальный,Удалённый,Статус,Время,Безопасность,Уровень",
        'about': "О программе",
        'about_title': "О программе I See You",
        'about_text': """I See You - продвинутый монитор сети v2.0

Разработчик: Хайдер Карим (حيدر كريم)

Продвинутый инструмент мониторинга сети с оценкой
безопасности, многоязычной поддержкой и улучшенной
производительностью.

Возможности:
• Мониторинг сетевых соединений в реальном времени
• Оценка рисков безопасности
• Многоязычная поддержка (EN/AR/RU)
• Тёмная/светлая темы
• Экспорт в CSV
• Продвинутая фильтрация и поиск

© 2025 Хайдер Карим. Все права защищены.""",
    }
}


def tr(lang: str, key: str) -> str:
    return I18N.get(lang, I18N['en']).get(key, key)


# ==========================
# Enhanced Data Classes
# ==========================

@dataclass
class ConnectionRow:
    process: str
    pid: int
    path: str
    local: str
    remote: str
    status: str
    timestamp: str
    sec_score: int
    sec_label: str  # internal label in EN: Safe/Medium/Risk


SAFE_PORTS = {443, 80, 853, 993, 995, 587, 22, 53, 8080, 8443}
DANGEROUS_PORTS = {23, 6667, 31337, 1337, 12345, 54321}
SYSTEM_PATHS = [
    r"\program files", r"\windows\system32", r"\windows\syswow64",
    r"/usr/bin", r"/usr/local/bin", r"/bin", r"/sbin", r"/usr/sbin"
]
TEMP_PATHS = [
    r"\temp", r"\appdata\local\temp", r"\appdata\roaming\temp",
    "/tmp", "/var/tmp", "/temp"
]


class SecurityAssessor:
    """Enhanced security assessment with better caching and scoring"""

    def __init__(self):
        self.sign_cache = LRUCacheWithTTL(max_size=200, ttl=600)  # 10 minutes TTL
        logger.info("SecurityAssessor initialized with enhanced caching")

    def check_signed(self, exe_path: str) -> Optional[bool]:
        """Check if executable is digitally signed (with enhanced caching)"""
        if not exe_path or exe_path == "Unknown":
            return None

        if not os.path.exists(exe_path):
            logger.debug(f"Executable not found: {exe_path}")
            return None

        # Check cache first
        cached = self.sign_cache.get(exe_path)
        if cached is not None:
            return cached

        signed = None
        if os.name == "nt":
            try:
                ps_cmd = f"(Get-AuthenticodeSignature -FilePath '{exe_path}').Status"
                rc, out, err = run_powershell(ps_cmd, timeout=5.0)

                if rc == 0 and out:
                    if "Valid" in out:
                        signed = True
                        logger.debug(f"Valid signature: {exe_path}")
                    elif "NotSigned" in out:
                        signed = False
                        logger.debug(f"Not signed: {exe_path}")
                    else:
                        logger.debug(f"Unknown signature status: {out}")
                else:
                    logger.warning(f"Failed to check signature for {exe_path}: {err}")

            except Exception as e:
                logger.error(f"Error checking signature for {exe_path}: {e}")

        # Cache the result
        if signed is not None:
            self.sign_cache.set(exe_path, signed)

        return signed

    def score(self, process: str, exe_path: str, remote_ip: str,
              remote_port: Optional[int], is_admin_proc: bool) -> Tuple[int, str]:
        """Enhanced security scoring algorithm"""
        score = 50  # Start with neutral score

        try:
            # Digital signature check (weight: high)
            signed = self.check_signed(exe_path)
            if signed is True:
                score += 25
            elif signed is False:
                score -= 15

            # Path analysis (weight: medium)
            if exe_path:
                path_lower = exe_path.lower()

                # System directories (trusted)
                if any(sys_path in path_lower for sys_path in SYSTEM_PATHS):
                    score += 15

                # Temporary directories (suspicious)
                elif any(temp_path in path_lower for temp_path in TEMP_PATHS):
                    score -= 20

                # User downloads/desktop (potentially risky)
                elif any(risky in path_lower for risky in ["downloads", "desktop", "temp"]):
                    score -= 12

                # Program Files but unsigned (mixed signal)
                elif "program files" in path_lower and signed is False:
                    score -= 5

            # Network analysis (weight: medium)
            if remote_ip:
                try:
                    ip_obj = ipaddress.ip_address(remote_ip)

                    # Private IPs are generally safer
                    if ip_obj.is_private:
                        score += 8
                    # Loopback is very safe
                    elif ip_obj.is_loopback:
                        score += 15
                    # Multicast less concerning
                    elif ip_obj.is_multicast:
                        score += 3
                    # Global IPs need more scrutiny
                    else:
                        score -= 5

                except Exception as e:
                    logger.debug(f"Error analyzing IP {remote_ip}: {e}")

            # Port analysis (weight: high for known dangerous ports)
            if remote_port:
                if remote_port in SAFE_PORTS:
                    bonus = 15 if remote_port == 443 else 10
                    score += bonus
                elif remote_port in DANGEROUS_PORTS:
                    score -= 25
                elif remote_port < 1024:  # Well-known ports
                    score += 5
                elif remote_port > 49152:  # Dynamic/private ports
                    score -= 3

            # Process name analysis
            process_lower = process.lower() if process else ""
            suspicious_names = [
                "unknown", "temp", "test", "hack", "crack", "keylog",
                "trojan", "virus", "malware", "backdoor"
            ]
            if any(sus in process_lower for sus in suspicious_names):
                score -= 20

            # System process bonus
            trusted_processes = [
                "svchost.exe", "system", "explorer.exe", "winlogon.exe",
                "chrome.exe", "firefox.exe", "edge.exe", "teams.exe"
            ]
            if any(trusted in process_lower for trusted in trusted_processes):
                score += 10

            # Admin process penalty (higher risk)
            if is_admin_proc:
                score -= 8

            # Ensure score is within bounds
            score = max(0, min(100, score))

            # Determine risk label
            if score >= 75:
                label = "Safe"
            elif score >= 45:
                label = "Medium"
            else:
                label = "Risk"

            logger.debug(f"Security score for {process}: {score} ({label})")
            return score, label

        except Exception as e:
            logger.error(f"Error in security scoring: {e}")
            return 50, "Medium"  # Safe fallback

    def get_cache_stats(self) -> dict:
        """Get cache statistics for monitoring"""
        return self.sign_cache.stats()


# ==========================
# Enhanced Worker with Batch Processing
# ==========================

class MonitorWorker(QObject):
    snapshot = Signal(list)  # list[ConnectionRow]
    error = Signal(str)
    stats = Signal(dict)  # Performance statistics

    def __init__(self, interval_ms: int = 1000):
        super().__init__()
        self._running = False
        self.interval_ms = interval_ms
        self.assessor = SecurityAssessor()
        self.batch_size = 50  # Process connections in batches
        self.stats_data = {
            'total_processed': 0,
            'errors': 0,
            'last_batch_time': 0,
            'cache_hits': 0
        }
        logger.info(f"MonitorWorker initialized with interval {interval_ms}ms")

    def set_interval(self, ms: int):
        self.interval_ms = max(200, ms)
        logger.info(f"Monitor interval updated to {self.interval_ms}ms")

    def _is_admin_process(self, pid: int) -> bool:
        """Check if process is running with admin privileges"""
        if os.name != "nt":
            try:
                process = psutil.Process(pid)
                # On Unix systems, check if process is owned by root
                return process.uids().real == 0
            except Exception as e:
                logger.debug(f"Error checking admin status for PID {pid}: {e}")
                return False

        try:
            process = psutil.Process(pid)
            username = process.username().lower()
            return "system" in username or "administrator" in username
        except Exception as e:
            logger.debug(f"Error checking admin status for PID {pid}: {e}")
            return False

    def process_batch(self, connections_batch: List) -> List[ConnectionRow]:
        """Process a batch of connections for better performance"""
        rows = []

        for conn in connections_batch:
            if not self._running:  # Check if we should stop
                break

            try:
                if conn.pid is None:
                    continue

                # Filter by connection status
                if conn.status not in ("ESTABLISHED", "SYN_SENT", "SYN_RECV", "LISTEN"):
                    continue

                process = psutil.Process(conn.pid)
                proc_name = process.name()

                try:
                    exe_path = process.exe()
                except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                    exe_path = "Unknown"

                # Format addresses
                local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""

                remote_ip = ""
                remote_port = None
                if conn.raddr:
                    remote_ip = getattr(conn.raddr, "ip", "")
                    remote_port = getattr(conn.raddr, "port", None)

                remote = f"{remote_ip}:{remote_port}" if remote_ip and remote_port else ""

                # Timestamp
                timestamp = datetime.now().strftime("%H:%M:%S")

                # Security assessment
                is_admin = self._is_admin_process(conn.pid)
                score, label = self.assessor.score(
                    proc_name, exe_path, remote_ip, remote_port, is_admin
                )

                rows.append(ConnectionRow(
                    process=proc_name,
                    pid=conn.pid,
                    path=exe_path,
                    local=local,
                    remote=remote,
                    status=conn.status,
                    timestamp=timestamp,
                    sec_score=score,
                    sec_label=label
                ))

                self.stats_data['total_processed'] += 1

            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                logger.debug(f"Process access denied/not found for PID {conn.pid}: {e}")
                continue
            except Exception as e:
                logger.error(f"Error processing connection {conn}: {e}")
                self.stats_data['errors'] += 1
                continue

        return rows

    def collect_once(self) -> List[ConnectionRow]:
        """Enhanced collection with batch processing and error handling"""
        start_time = time.time()
        all_rows = []

        try:
            logger.debug("Starting connection collection")
            connections = psutil.net_connections(kind='inet')
            logger.debug(f"Found {len(connections)} total connections")

            # Process in batches for better performance
            for i in range(0, len(connections), self.batch_size):
                if not self._running:
                    break

                batch = connections[i:i + self.batch_size]
                batch_rows = self.process_batch(batch)
                all_rows.extend(batch_rows)

                # Small pause between batches to not overwhelm system
                if i + self.batch_size < len(connections):
                    time.sleep(0.01)

            # Update statistics
            batch_time = time.time() - start_time
            self.stats_data['last_batch_time'] = batch_time
            cache_stats = self.assessor.get_cache_stats()

            # Emit statistics
            self.stats.emit({
                'connections_found': len(connections),
                'connections_processed': len(all_rows),
                'batch_time': batch_time,
                'total_processed': self.stats_data['total_processed'],
                'errors': self.stats_data['errors'],
                'cache_size': cache_stats['size']
            })

            logger.debug(f"Collection completed: {len(all_rows)} rows in {batch_time:.2f}s")

        except Exception as e:
            error_msg = f"Error during connection collection: {e}"
            logger.error(error_msg)
            self.error.emit(error_msg)
            self.stats_data['errors'] += 1

        return all_rows

    def start(self):
        """Start monitoring loop"""
        logger.info("Starting network monitoring")
        self._running = True

        while self._running:
            try:
                rows = self.collect_once()
                if self._running:  # Only emit if still running
                    self.snapshot.emit(rows)

                # Smart sleep with periodic checks
                total_sleep = self.interval_ms / 1000.0
                sleep_chunk = 0.05  # Check every 50ms
                elapsed = 0

                while self._running and elapsed < total_sleep:
                    time.sleep(sleep_chunk)
                    elapsed += sleep_chunk

            except Exception as e:
                error_msg = f"Error in monitoring loop: {e}"
                logger.error(error_msg)
                self.error.emit(error_msg)
                time.sleep(1)  # Prevent tight error loops

        logger.info("Network monitoring stopped")

    def stop(self):
        """Stop monitoring"""
        logger.info("Stopping network monitoring")
        self._running = False


# ==========================
# Table Model (unchanged but with better error handling)
# ==========================

class ConnectionsModel(QAbstractTableModel):
    def __init__(self, headers: List[str], dark_cmd_mode: bool = False):
        super().__init__()
        self._rows: List[ConnectionRow] = []
        self._headers = headers
        self.dark_cmd_mode = dark_cmd_mode

    def set_dark_cmd(self, enabled: bool):
        self.dark_cmd_mode = enabled
        self.layoutChanged.emit()

    def set_headers(self, headers: List[str]):
        self.beginResetModel()
        self._headers = headers
        self.endResetModel()

    def set_rows(self, rows: List[ConnectionRow]):
        try:
            self.beginResetModel()
            self._rows = rows[:]  # Create a copy
            self.endResetModel()
        except Exception as e:
            logger.error(f"Error setting table rows: {e}")

    def rowCount(self, parent=QModelIndex()) -> int:
        return len(self._rows)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(self._headers)

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole):
        try:
            if not index.isValid() or index.row() >= len(self._rows):
                return None

            r = self._rows[index.row()]
            c = index.column()

            if role in (Qt.DisplayRole, Qt.EditRole):
                data_values = [
                    r.process, str(r.pid), r.path, r.local, r.remote,
                    r.status, r.timestamp, r.sec_score, r.sec_label
                ]
                if c < len(data_values):
                    return data_values[c]
                return None

            if role == Qt.TextAlignmentRole:
                if c in (1, 7):  # PID and Security columns
                    return Qt.AlignCenter
                return Qt.AlignVCenter | Qt.AlignLeft

            # cmd-style green in dark mode
            if role == Qt.ForegroundRole and self.dark_cmd_mode:
                return QColor("#00FF00")

            # normal coloring for Level column in light mode
            if role == Qt.ForegroundRole and not self.dark_cmd_mode and c == 8:
                if r.sec_label == "Safe":
                    return QColor("#2e7d32")  # green
                elif r.sec_label == "Medium":
                    return QColor("#ef6c00")  # orange
                else:
                    return QColor("#b71c1c")  # red

        except Exception as e:
            logger.error(f"Error in table data method: {e}")

        return None

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole):
        if role != Qt.DisplayRole:
            return None
        if orientation == Qt.Horizontal and section < len(self._headers):
            return self._headers[section]
        elif orientation == Qt.Vertical:
            return str(section + 1)
        return None

    def get_row(self, i: int) -> Optional[ConnectionRow]:
        try:
            return self._rows[i] if 0 <= i < len(self._rows) else None
        except Exception as e:
            logger.error(f"Error getting row {i}: {e}")
            return None


# ==========================
# Enhanced Settings Dialog
# ==========================

class SettingsDialog(QDialog):
    def __init__(self, parent=None, lang='en', interval_ms=1000, only_est=True, autostart=True, theme='dark'):
        super().__init__(parent)
        self.lang = lang
        self.setWindowTitle(tr(lang, 'settings'))
        self.setModal(True)
        self.resize(400, 300)

        # Interval setting with validation
        self.interval_spin = QSpinBox()
        self.interval_spin.setRange(200, 60000)
        self.interval_spin.setSingleStep(100)
        self.interval_spin.setSuffix(" ms")
        self.interval_spin.setValue(max(200, min(60000, interval_ms)))

        # Checkboxes
        self.chk_only_est = QCheckBox(tr(lang, 'only_est'))
        self.chk_only_est.setChecked(only_est)

        self.chk_autostart = QCheckBox(tr(lang, 'autostart'))
        self.chk_autostart.setChecked(autostart)

        # Theme selection
        self.theme_combo = QComboBox()
        self.theme_combo.addItems([tr(lang, 'dark'), tr(lang, 'light')])
        self.theme_combo.setCurrentIndex(0 if theme == 'dark' else 1)

        # Form layout
        form = QFormLayout()
        form.addRow(tr(lang, 'update_interval'), self.interval_spin)
        form.addRow("", self.chk_only_est)
        form.addRow("", self.chk_autostart)
        form.addRow(tr(lang, 'theme'), self.theme_combo)

        # Buttons
        btns = QHBoxLayout()
        ok = QPushButton(tr(lang, 'ok'))
        cancel = QPushButton(tr(lang, 'cancel'))
        btns.addWidget(ok)
        btns.addWidget(cancel)

        ok.clicked.connect(self.accept)
        cancel.clicked.connect(self.reject)

        # Main layout
        root = QVBoxLayout()
        root.addLayout(form)
        root.addStretch()
        root.addLayout(btns)
        self.setLayout(root)

    def values(self):
        theme = 'dark' if self.theme_combo.currentIndex() == 0 else 'light'
        return {
            "interval_ms": self.interval_spin.value(),
            "only_established": self.chk_only_est.isChecked(),
            "autostart": self.chk_autostart.isChecked(),
            "theme": theme
        }


# ==========================
# Enhanced Main Window
# ==========================

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        logger.info("Initializing main window")

        # Enhanced config management
        self.cfg_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), "settings.json")
        self.config = self.load_config()
        self.lang = self.config.get("lang", "en")
        self.theme = self.config.get("theme", "dark")

        # Validate configuration
        if not validate_config(self.config):
            logger.warning("Invalid configuration detected, using defaults")
            self.config = self.get_default_config()

        # UI setup
        self.setup_ui()

        # Worker setup
        self.worker_thread: Optional[QThread] = None
        self.worker: Optional[MonitorWorker] = None

        # Apply theme
        self.apply_theme(self.theme)

        # Statistics tracking
        self.connection_stats = {"total": 0, "filtered": 0, "errors": 0}

        # Auto-start with validation
        if self.config.get("autostart", True):
            QTimer.singleShot(500, self.start_monitor)

        logger.info("Main window initialization completed")

    def setup_ui(self):
        """Setup user interface components"""
        # Layout direction for Arabic
        self.apply_layout_direction()

        self.setWindowTitle(tr(self.lang, 'app_title'))
        self.resize(1200, 740)

        # Central widget
        cw = QWidget()
        self.setCentralWidget(cw)
        vbox = QVBoxLayout(cw)

        # Toolbar
        self.setup_toolbar()

        # Search and filter section
        self.setup_search_filter(vbox)

        # Table setup
        self.setup_table(vbox)

        # Status bar
        self.setup_status_bar()

        # Connect signals
        self.connect_signals()

        # Set column widths
        self.set_column_widths()

    def setup_toolbar(self):
        """Setup application toolbar"""
        tb = QToolBar("Main")
        tb.setMovable(False)
        self.addToolBar(Qt.TopToolBarArea, tb)

        # Actions
        self.act_start = QAction(tr(self.lang, 'start'), self)
        self.act_stop = QAction(tr(self.lang, 'stop'), self)
        self.act_stop.setEnabled(False)
        self.act_export = QAction(tr(self.lang, 'export_csv'), self)
        self.act_settings = QAction(tr(self.lang, 'settings'), self)
        self.act_about = QAction(tr(self.lang, 'about'), self)
        self.act_theme_toggle = QAction(
            f"{tr(self.lang, 'theme')}: {tr(self.lang, 'dark') if self.theme == 'dark' else tr(self.lang, 'light')}",
            self
        )
        self.act_quit = QAction(tr(self.lang, 'quit'), self)

        # Add actions to toolbar
        tb.addAction(self.act_start)
        tb.addAction(self.act_stop)
        tb.addSeparator()
        tb.addAction(self.act_export)
        tb.addSeparator()
        tb.addAction(self.act_settings)
        tb.addAction(self.act_about)
        tb.addSeparator()
        tb.addAction(self.act_theme_toggle)
        tb.addSeparator()
        tb.addAction(self.act_quit)

    def setup_search_filter(self, parent_layout):
        """Setup search and filter controls"""
        filter_box = QHBoxLayout()

        # Search
        self.lbl_search = QLabel(tr(self.lang, 'search'))
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText(tr(self.lang, 'filter_placeholder'))

        # Level filter
        self.lbl_level = QLabel(tr(self.lang, 'level'))
        self.cmb_level = QComboBox()
        self.cmb_level.addItems([
            tr(self.lang, 'all'),
            tr(self.lang, 'safe'),
            tr(self.lang, 'medium'),
            tr(self.lang, 'risk')
        ])

        # Language selector
        self.lbl_lang = QLabel(tr(self.lang, 'language'))
        self.cmb_lang = QComboBox()
        self.cmb_lang.addItems(["English", "العربية", "Русский"])
        self.cmb_lang.setCurrentIndex({'en': 0, 'ar': 1, 'ru': 2}[self.lang])

        # Admin status
        self.lbl_admin = QLabel(
            tr(self.lang, 'admin_ok') if is_admin() else tr(self.lang, 'admin_tip')
        )
        self.lbl_admin.setStyleSheet("color:#9ccc65;" if is_admin() else "color:#ffca28;")

        # Layout
        filter_box.addWidget(self.lbl_search)
        filter_box.addWidget(self.search_edit, 1)
        filter_box.addWidget(self.lbl_level)
        filter_box.addWidget(self.cmb_level)
        filter_box.addStretch(1)
        filter_box.addWidget(self.lbl_lang)
        filter_box.addWidget(self.cmb_lang)
        filter_box.addWidget(self.lbl_admin)

        parent_layout.addLayout(filter_box)

    def setup_table(self, parent_layout):
        """Setup data table"""
        # Headers by language
        self.headers = [h.strip() for h in tr(self.lang, 'columns').split(",")]

        # Model and proxy
        self.model = ConnectionsModel(headers=self.headers, dark_cmd_mode=(self.theme == 'dark'))
        self.proxy = QSortFilterProxyModel(self)
        self.proxy.setSourceModel(self.model)
        self.proxy.setFilterCaseSensitivity(Qt.CaseInsensitive)
        self.proxy.setFilterKeyColumn(-1)

        # Table view
        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setAlternatingRowColors(False)
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setSelectionMode(QTableView.SingleSelection)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)

        parent_layout.addWidget(self.table, 1)

    def setup_status_bar(self):
        """Setup status bar"""
        sb = QStatusBar()
        self.setStatusBar(sb)
        self.lbl_status = QLabel(tr(self.lang, 'ready'))
        sb.addPermanentWidget(self.lbl_status)

    def connect_signals(self):
        """Connect all UI signals"""
        # Toolbar actions
        self.act_start.triggered.connect(self.start_monitor)
        self.act_stop.triggered.connect(self.stop_monitor)
        self.act_export.triggered.connect(self.export_csv)
        self.act_quit.triggered.connect(self.close)
        self.act_settings.triggered.connect(self.open_settings)
        self.act_about.triggered.connect(self.show_about)
        self.act_theme_toggle.triggered.connect(self.toggle_theme)

        # Filters
        self.search_edit.textChanged.connect(self.update_filter)
        self.cmb_level.currentTextChanged.connect(self.update_filter)
        self.cmb_lang.currentIndexChanged.connect(self.change_language)

        # Table
        self.table.customContextMenuRequested.connect(self.open_context_menu)

    def set_column_widths(self):
        """Set optimal column widths"""
        widths = [170, 70, 300, 150, 170, 120, 90, 100, 100]
        for i, width in enumerate(widths):
            if i < self.table.model().columnCount():
                self.table.setColumnWidth(i, width)

    def get_default_config(self) -> dict:
        """Get default configuration"""
        return {
            "interval_ms": 1000,
            "only_established": True,
            "autostart": True,
            "lang": "en",
            "theme": "dark"
        }

    def load_config(self) -> dict:
        """Enhanced configuration loading with validation"""
        try:
            if os.path.exists(self.cfg_path):
                with open(self.cfg_path, "r", encoding="utf-8") as f:
                    config = json.load(f)
                    logger.info("Configuration loaded successfully")
                    return config
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in config file: {e}")
        except Exception as e:
            logger.error(f"Error loading config: {e}")

        logger.info("Using default configuration")
        return self.get_default_config()

    def save_config(self):
        """Enhanced configuration saving with validation"""
        try:
            # Validate before saving
            if validate_config(self.config):
                # Ensure directory exists
                os.makedirs(os.path.dirname(self.cfg_path), exist_ok=True)

                with open(self.cfg_path, "w", encoding="utf-8") as f:
                    json.dump(self.config, f, indent=2, ensure_ascii=False)
                logger.info("Configuration saved successfully")
            else:
                logger.error("Configuration validation failed, not saving")
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")

    # ---------- Theme & Language Methods ----------

    def apply_layout_direction(self):
        """Apply layout direction based on language"""
        try:
            if self.lang == 'ar':
                QApplication.setLayoutDirection(Qt.RightToLeft)
                QLocale.setDefault(QLocale(QLocale.Arabic))
            else:
                QApplication.setLayoutDirection(Qt.LeftToRight)
                if self.lang == 'ru':
                    QLocale.setDefault(QLocale(QLocale.Russian))
                else:
                    QLocale.setDefault(QLocale(QLocale.English))
        except Exception as e:
            logger.error(f"Error applying layout direction: {e}")

    def apply_theme(self, theme: str):
        """Enhanced theme application"""
        try:
            if theme == 'dark':
                self.apply_dark_theme()
            else:
                self.apply_light_theme()

            # Update theme toggle caption
            self.act_theme_toggle.setText(
                f"{tr(self.lang, 'theme')}: {tr(self.lang, 'dark') if theme == 'dark' else tr(self.lang, 'light')}"
            )
            self.theme = theme
            self.config['theme'] = theme
            self.save_config()

            logger.info(f"Applied {theme} theme")

        except Exception as e:
            logger.error(f"Error applying theme: {e}")

    def apply_dark_theme(self):
        """Apply dark theme styling"""
        QApplication.setStyle(QStyleFactory.create("Fusion"))
        p = QPalette()
        p.setColor(QPalette.Window, QColor(0, 0, 0))
        p.setColor(QPalette.WindowText, QColor(0, 255, 0))
        p.setColor(QPalette.Base, QColor(0, 0, 0))
        p.setColor(QPalette.AlternateBase, QColor(0, 0, 0))
        p.setColor(QPalette.ToolTipBase, QColor(0, 0, 0))
        p.setColor(QPalette.ToolTipText, QColor(0, 255, 0))
        p.setColor(QPalette.Text, QColor(0, 255, 0))
        p.setColor(QPalette.Button, QColor(10, 10, 10))
        p.setColor(QPalette.ButtonText, QColor(0, 255, 0))
        p.setColor(QPalette.Highlight, QColor(0, 120, 0))
        p.setColor(QPalette.HighlightedText, QColor(0, 255, 0))
        QApplication.setPalette(p)

        self.model.set_dark_cmd(True)
        self.setStyleSheet("""
            QToolBar { spacing:6px; }
            QTableView { 
                gridline-color: #004400; 
                selection-background-color:#003300; 
                selection-color:#00FF00; 
            }
            QHeaderView::section { 
                background-color:#001a00; 
                color:#00FF00; 
                padding:6px; 
                border:1px solid #003300; 
            }
            QLabel, QLineEdit, QComboBox, QPushButton { color:#00FF00; }
            QLineEdit, QComboBox { 
                background:#000; 
                border:1px solid #004400; 
                padding:4px 6px; 
            }
            QStatusBar { color:#00FF00; }
        """)

    def apply_light_theme(self):
        """Apply light theme styling"""
        QApplication.setStyle(QStyleFactory.create("Fusion"))
        p = QPalette()
        p.setColor(QPalette.Window, QColor(245, 245, 245))
        p.setColor(QPalette.WindowText, Qt.black)
        p.setColor(QPalette.Base, Qt.white)
        p.setColor(QPalette.AlternateBase, QColor(245, 245, 245))
        p.setColor(QPalette.Text, Qt.black)
        p.setColor(QPalette.Button, QColor(245, 245, 245))
        p.setColor(QPalette.ButtonText, Qt.black)
        p.setColor(QPalette.Highlight, QColor(64, 128, 255))
        p.setColor(QPalette.HighlightedText, Qt.white)
        QApplication.setPalette(p)

        self.model.set_dark_cmd(False)
        self.setStyleSheet("""
            QToolBar { spacing:6px; }
            QTableView { 
                gridline-color:#bbb; 
                selection-background-color:#dce6ff; 
                selection-color:#000; 
            }
            QHeaderView::section { 
                background-color:#f0f0f0; 
                color:#333; 
                padding:6px; 
                border:1px solid #d0d0d0; 
            }
            QLineEdit, QComboBox { 
                background:#fff; 
                color:#000; 
                border:1px solid #bbb; 
                padding:4px 6px; 
            }
        """)

    def toggle_theme(self):
        """Toggle between dark and light themes"""
        new_theme = 'light' if self.theme == 'dark' else 'dark'
        self.apply_theme(new_theme)

    def change_language(self, idx: int):
        """Enhanced language change with validation"""
        try:
            lang_map = {0: 'en', 1: 'ar', 2: 'ru'}
            if idx not in lang_map:
                logger.error(f"Invalid language index: {idx}")
                return

            self.lang = lang_map[idx]
            self.config['lang'] = self.lang
            self.save_config()

            # Apply layout direction
            self.apply_layout_direction()

            # Update all UI texts
            self.update_ui_texts()

            logger.info(f"Language changed to: {self.lang}")

        except Exception as e:
            logger.error(f"Error changing language: {e}")

    def update_ui_texts(self):
        """Update all UI texts for current language"""
        try:
            # Window title
            self.setWindowTitle(tr(self.lang, 'app_title'))

            # Actions
            self.act_start.setText(tr(self.lang, 'start'))
            self.act_stop.setText(tr(self.lang, 'stop'))
            self.act_export.setText(tr(self.lang, 'export_csv'))
            self.act_settings.setText(tr(self.lang, 'settings'))
            self.act_about.setText(tr(self.lang, 'about'))
            self.act_quit.setText(tr(self.lang, 'quit'))
            self.act_theme_toggle.setText(
                f"{tr(self.lang, 'theme')}: {tr(self.lang, 'dark') if self.theme == 'dark' else tr(self.lang, 'light')}"
            )

            # Labels
            self.lbl_search.setText(tr(self.lang, 'search'))
            self.search_edit.setPlaceholderText(tr(self.lang, 'filter_placeholder'))
            self.lbl_level.setText(tr(self.lang, 'level'))
            self.lbl_lang.setText(tr(self.lang, 'language'))
            self.lbl_admin.setText(tr(self.lang, 'admin_ok') if is_admin() else tr(self.lang, 'admin_tip'))
            self.lbl_status.setText(tr(self.lang, 'ready'))

            # Level combo
            current_level = self.cmb_level.currentIndex()
            self.cmb_level.blockSignals(True)
            self.cmb_level.clear()
            self.cmb_level.addItems([
                tr(self.lang, 'all'),
                tr(self.lang, 'safe'),
                tr(self.lang, 'medium'),
                tr(self.lang, 'risk')
            ])
            self.cmb_level.setCurrentIndex(min(current_level, 3))
            self.cmb_level.blockSignals(False)

            # Table headers
            self.headers = [h.strip() for h in tr(self.lang, 'columns').split(",")]
            self.model.set_headers(self.headers)

            # Refresh filter
            self.update_filter()

        except Exception as e:
            logger.error(f"Error updating UI texts: {e}")

    # ---------- Filtering and Context Menu ----------

    def level_display_to_internal(self, display: str) -> str:
        """Map translated level display to internal labels"""
        level_mappings = {
            tr(self.lang, 'safe'): "Safe",
            tr(self.lang, 'medium'): "Medium",
            tr(self.lang, 'risk'): "Risk",
            "Safe": "Safe",
            "Medium": "Medium",
            "Risk": "Risk"
        }
        return level_mappings.get(display, "All")

    def update_filter(self):
        """Enhanced filter update with better regex handling"""
        try:
            text = self.search_edit.text().strip()
            level_display = self.cmb_level.currentText()
            level_internal = self.level_display_to_internal(level_display)

            parts = []
            if text:
                # Escape special regex characters for safety
                escaped_text = QRegularExpression.escape(text)
                parts.append(f"(?=.*{escaped_text})")

            if level_internal != "All":
                escaped_level = QRegularExpression.escape(level_internal)
                parts.append(f"(?=.*{escaped_level})")

            pattern = "".join(parts) if parts else ".*"

            # Apply filter
            regex = QRegularExpression(pattern, QRegularExpression.CaseInsensitiveOption)
            self.proxy.setFilterRegularExpression(regex)

            # Update statistics
            self.connection_stats["filtered"] = self.proxy.rowCount()

        except Exception as e:
            logger.error(f"Error updating filter: {e}")

    def open_context_menu(self, pos):
        """Enhanced context menu with error handling"""
        try:
            idx = self.table.indexAt(pos)
            if not idx.isValid():
                return

            global_pos = self.table.viewport().mapToGlobal(pos)
            menu = QMenu(self)

            # Create actions
            act_copy_row = QAction(tr(self.lang, 'copy_row'), self)
            act_open_path = QAction(tr(self.lang, 'open_path'), self)
            act_kill = QAction(tr(self.lang, 'terminate'), self)

            # Connect actions
            act_copy_row.triggered.connect(self.copy_selected_row)
            act_open_path.triggered.connect(self.open_selected_path)
            act_kill.triggered.connect(self.kill_selected_process)

            # Build menu
            menu.addAction(act_copy_row)
            menu.addAction(act_open_path)
            menu.addSeparator()
            menu.addAction(act_kill)

            # Show menu
            menu.exec(global_pos)

        except Exception as e:
            logger.error(f"Error opening context menu: {e}")

    def copy_selected_row(self):
        """Enhanced row copying with error handling"""
        try:
            current_idx = self.table.currentIndex()
            if not current_idx.isValid():
                return

            source_row = self.proxy.mapToSource(current_idx).row()
            row_data = self.model.get_row(source_row)

            if not row_data:
                return

            # Format data for clipboard
            formatted_text = (
                f"Process={row_data.process} | "
                f"PID={row_data.pid} | "
                f"Path={row_data.path} | "
                f"Local={row_data.local} | "
                f"Remote={row_data.remote} | "
                f"Status={row_data.status} | "
                f"Time={row_data.timestamp} | "
                f"Security={row_data.sec_score} | "
                f"Level={row_data.sec_label}"
            )

            QApplication.clipboard().setText(formatted_text)
            self.statusBar().showMessage(tr(self.lang, 'row_copied'), 2000)
            logger.info("Row data copied to clipboard")

        except Exception as e:
            logger.error(f"Error copying row: {e}")
            self.statusBar().showMessage(f"Copy failed: {e}", 3000)

    def open_selected_path(self):
        """Enhanced path opening with better error handling"""
        try:
            current_idx = self.table.currentIndex()
            if not current_idx.isValid():
                return

            source_row = self.proxy.mapToSource(current_idx).row()
            row_data = self.model.get_row(source_row)

            if not row_data:
                return

            path = row_data.path
            if not path or path == "Unknown":
                QMessageBox.information(self, tr(self.lang, 'open_path'), tr(self.lang, 'open_info'))
                return

            if not os.path.exists(path):
                QMessageBox.warning(
                    self,
                    tr(self.lang, 'open_path'),
                    f"File not found: {path}"
                )
                return

            # Platform-specific file opening
            if os.name == "nt":
                subprocess.Popen(['explorer', '/select,', path], shell=False)
            elif sys.platform == "darwin":  # macOS
                subprocess.Popen(['open', '-R', path])
            else:  # Linux and others
                subprocess.Popen(['xdg-open', os.path.dirname(path)])

            logger.info(f"Opened file location: {path}")

        except Exception as e:
            logger.error(f"Error opening file location: {e}")
            QMessageBox.warning(
                self,
                tr(self.lang, 'open_path'),
                f"Failed to open location: {e}"
            )

    def kill_selected_process(self):
        """Enhanced process termination with safety checks"""
        try:
            current_idx = self.table.currentIndex()
            if not current_idx.isValid():
                return

            source_row = self.proxy.mapToSource(current_idx).row()
            row_data = self.model.get_row(source_row)

            if not row_data:
                return

            pid = row_data.pid
            process_name = row_data.process

            # Safety check - don't allow terminating critical system processes
            critical_processes = [
                "system", "smss.exe", "csrss.exe", "wininit.exe",
                "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe",
                "explorer.exe", "dwm.exe"
            ]

            if process_name.lower() in critical_processes:
                QMessageBox.warning(
                    self,
                    tr(self.lang, 'terminate'),
                    f"Cannot terminate critical system process: {process_name}"
                )
                return

            # Confirm termination
            msg = tr(self.lang, 'ask_terminate').format(proc=process_name, pid=pid)
            reply = QMessageBox.question(
                self,
                tr(self.lang, 'terminate'),
                msg,
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No  # Default to No for safety
            )

            if reply == QMessageBox.Yes:
                try:
                    process = psutil.Process(pid)
                    process.terminate()
                    self.statusBar().showMessage(
                        f"Process {process_name} (PID {pid}) terminated",
                        3000
                    )
                    logger.info(f"Terminated process: {process_name} (PID {pid})")

                except psutil.NoSuchProcess:
                    QMessageBox.information(
                        self,
                        tr(self.lang, 'terminate'),
                        f"Process {process_name} (PID {pid}) no longer exists"
                    )
                except psutil.AccessDenied:
                    QMessageBox.warning(
                        self,
                        tr(self.lang, 'terminate'),
                        f"Access denied. Cannot terminate {process_name} (PID {pid})"
                    )
                except Exception as e:
                    logger.error(f"Error terminating process {pid}: {e}")
                    QMessageBox.warning(
                        self,
                        tr(self.lang, 'terminate'),
                        f"Failed to terminate process: {e}"
                    )

        except Exception as e:
            logger.error(f"Error in kill_selected_process: {e}")

    # ---------- Export Functionality ----------

    def export_csv(self):
        """Enhanced CSV export with better error handling and validation"""
        try:
            # Get save location
            default_filename = f"network_connections_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                tr(self.lang, 'export_title'),
                default_filename,
                tr(self.lang, 'export_filter')
            )

            if not file_path:
                return

            # Ensure .csv extension
            if not file_path.lower().endswith('.csv'):
                file_path += '.csv'

            # Export data
            import csv
            rows_exported = 0

            with open(file_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)

                # Write headers
                writer.writerow(self.headers)

                # Write data rows
                for row_idx in range(self.proxy.rowCount()):
                    source_idx = self.proxy.mapToSource(self.proxy.index(row_idx, 0)).row()
                    row_data = self.model.get_row(source_idx)

                    if row_data:
                        writer.writerow([
                            row_data.process,
                            row_data.pid,
                            row_data.path,
                            row_data.local,
                            row_data.remote,
                            row_data.status,
                            row_data.timestamp,
                            row_data.sec_score,
                            row_data.sec_label
                        ])
                        rows_exported += 1

            # Success message
            success_msg = tr(self.lang, 'export_done').format(path=file_path)
            self.statusBar().showMessage(f"{success_msg} ({rows_exported} rows)", 5000)
            logger.info(f"Exported {rows_exported} rows to {file_path}")

        except Exception as e:
            error_msg = tr(self.lang, 'export_fail').format(err=str(e))
            logger.error(f"Export failed: {e}")
            QMessageBox.warning(self, tr(self.lang, 'export_title'), error_msg)

    # ---------- Monitor Control ----------

    def start_monitor(self):
        """Enhanced monitor start with better error handling"""
        try:
            # Check if already running
            if hasattr(self, 'worker') and self.worker:
                logger.warning("Monitor already running")
                return

            # Create worker thread
            self.worker_thread = QThread(self)
            self.worker = MonitorWorker(interval_ms=self.config.get("interval_ms", 1000))
            self.worker.moveToThread(self.worker_thread)

            # Connect signals
            self.worker_thread.started.connect(self.worker.start)
            self.worker.snapshot.connect(self.on_snapshot)
            self.worker.error.connect(self.on_error)
            self.worker.stats.connect(self.on_stats)

            # Start thread
            self.worker_thread.start()

            # Update UI
            self.act_start.setEnabled(False)
            self.act_stop.setEnabled(True)
            self.lbl_status.setText(tr(self.lang, 'monitoring'))

            logger.info("Network monitoring started")

        except Exception as e:
            logger.error(f"Failed to start monitoring: {e}")
            QMessageBox.warning(self, "Error", f"Failed to start monitoring: {e}")

    def stop_monitor(self):
        """Enhanced monitor stop with proper cleanup"""
        try:
            if not getattr(self, 'worker', None):
                return

            logger.info("Stopping network monitoring")

            # Stop worker
            self.worker.stop()

            # Wait for thread to finish
            if self.worker_thread and self.worker_thread.isRunning():
                self.worker_thread.quit()
                if not self.worker_thread.wait(3000):  # 3 second timeout
                    logger.warning("Worker thread did not stop gracefully, terminating")
                    self.worker_thread.terminate()
                    self.worker_thread.wait(1000)

            # Cleanup
            self.worker = None
            self.worker_thread = None

            # Update UI
            self.act_start.setEnabled(True)
            self.act_stop.setEnabled(False)
            self.lbl_status.setText(tr(self.lang, 'stopped'))

            logger.info("Network monitoring stopped")

        except Exception as e:
            logger.error(f"Error stopping monitor: {e}")

    def on_snapshot(self, rows: List[ConnectionRow]):
        """Enhanced snapshot handling with filtering and statistics"""
        try:
            # Apply established-only filter if configured
            if self.config.get("only_established", True):
                filtered_rows = [
                    r for r in rows
                    if r.status in ("ESTABLISHED", "SYN_SENT", "SYN_RECV")
                ]
            else:
                filtered_rows = rows

            # Update model
            self.model.set_rows(filtered_rows)

            # Update statistics
            self.connection_stats["total"] = len(rows)
            self.connection_stats["filtered"] = len(filtered_rows)

            # Refresh filter to maintain current view
            self.update_filter()

        except Exception as e:
            logger.error(f"Error handling snapshot: {e}")

    def on_error(self, msg: str):
        """Enhanced error handling"""
        try:
            error_display = tr(self.lang, 'error').format(msg=msg)
            self.statusBar().showMessage(error_display, 5000)
            self.connection_stats["errors"] += 1
            logger.error(f"Monitor error: {msg}")
        except Exception as e:
            logger.error(f"Error in error handler: {e}")

    def on_stats(self, stats: dict):
        """Handle performance statistics from worker"""
        try:
            # Log performance stats periodically
            if stats.get('total_processed', 0) % 100 == 0:  # Every 100 connections
                logger.info(f"Performance stats: {stats}")

            # Update status with connection count
            total = stats.get('connections_found', 0)
            processed = stats.get('connections_processed', 0)
            if total > 0:
                status_text = f"{tr(self.lang, 'monitoring')} ({processed}/{total})"
                self.lbl_status.setText(status_text)

        except Exception as e:
            logger.error(f"Error handling stats: {e}")

    # ---------- Settings Management ----------

    def open_settings(self):
        """Enhanced settings dialog with validation"""
        try:
            dialog = SettingsDialog(
                parent=self,
                lang=self.lang,
                interval_ms=self.config.get("interval_ms", 1000),
                only_est=self.config.get("only_established", True),
                autostart=self.config.get("autostart", True),
                theme=self.theme
            )

            if dialog.exec():
                new_values = dialog.values()

                # Validate new values
                test_config = self.config.copy()
                test_config.update(new_values)

                if validate_config(test_config):
                    # Apply changes
                    old_interval = self.config.get("interval_ms", 1000)
                    old_theme = self.config.get("theme", "dark")

                    self.config.update(new_values)
                    self.save_config()

                    # Update worker interval if changed
                    if (new_values["interval_ms"] != old_interval and
                            getattr(self, 'worker', None)):
                        self.worker.set_interval(new_values["interval_ms"])
                        logger.info(f"Updated monitor interval to {new_values['interval_ms']}ms")

                    # Apply theme if changed
                    if new_values["theme"] != old_theme:
                        self.apply_theme(new_values["theme"])

                    logger.info("Settings updated successfully")
                else:
                    QMessageBox.warning(
                        self,
                        tr(self.lang, 'settings'),
                        "Invalid settings configuration"
                    )

        except Exception as e:
            logger.error(f"Error in settings dialog: {e}")
            QMessageBox.warning(self, "Error", f"Settings error: {e}")

    def show_about(self):
        """Show about dialog with developer information"""
        try:
            about_dialog = QMessageBox(self)
            about_dialog.setWindowTitle(tr(self.lang, 'about_title'))
            about_dialog.setText(tr(self.lang, 'about_text'))
            about_dialog.setIcon(QMessageBox.Information)

            # Set custom button text
            about_dialog.setStandardButtons(QMessageBox.Ok)
            ok_button = about_dialog.button(QMessageBox.Ok)
            ok_button.setText(tr(self.lang, 'ok'))

            # Apply theme-appropriate styling
            if self.theme == 'dark':
                about_dialog.setStyleSheet("""
                    QMessageBox {
                        background-color: #000;
                        color: #00FF00;
                    }
                    QMessageBox QPushButton {
                        background-color: #001a00;
                        color: #00FF00;
                        border: 1px solid #004400;
                        padding: 6px 12px;
                        min-width: 60px;
                    }
                    QMessageBox QPushButton:hover {
                        background-color: #003300;
                    }
                """)

            about_dialog.exec()
            logger.info("About dialog shown")

        except Exception as e:
            logger.error(f"Error showing about dialog: {e}")

    # ---------- Cleanup and Exit ----------

    def closeEvent(self, event):
        """Enhanced cleanup on application exit"""
        try:
            logger.info("Application closing")

            # Stop monitoring
            self.stop_monitor()

            # Save configuration
            self.save_config()

            # Log final statistics
            logger.info(f"Final statistics: {self.connection_stats}")

            # Close logger handlers
            for handler in logger.handlers:
                handler.close()

            event.accept()

        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
            event.accept()  # Still close the application


# ==========================
# Enhanced Main Function
# ==========================

def main():
    """Enhanced main function with better error handling"""
    try:
        # Setup application
        app = QApplication(sys.argv)
        app.setApplicationName("I See You - Network Monitor")
        app.setApplicationVersion("2.0")
        app.setOrganizationName("Haider Kareem Development")
        app.setOrganizationDomain("haiderkareem.dev")

        # Create main window
        window = MainWindow()
        window.show()

        # Show admin warning if needed
        if os.name == "nt" and not is_admin():
            QTimer.singleShot(1000, lambda: window.statusBar().showMessage(
                tr(window.lang, 'admin_tip'), 7000
            ))

        logger.info("Application started successfully")

        # Run application
        exit_code = app.exec()
        logger.info(f"Application exited with code: {exit_code}")

        return exit_code

    except Exception as e:
        logger.error(f"Critical error in main: {e}")
        try:
            if 'app' in locals():
                QMessageBox.critical(None, "Critical Error", f"Application failed to start: {e}")
        except:
            print(f"Critical error: {e}")
        return 1


# ==========================
# Entry Point
# ==========================

if __name__ == "__main__":
    sys.exit(main())