import hashlib
from collections import namedtuple
from unittest.mock import MagicMock, mock_open, patch

import import_ipynb
import pytest

THIS_VARIANT = 1
reasons_to_skip = []

try:
    with open(".variant", "r") as f:
        student_variant = int(f.read().strip())
        if student_variant != THIS_VARIANT:
            reasons_to_skip.append(
                f"Пропускаем тесты для варианта {THIS_VARIANT}, так как у студента вариант {student_variant}"
            )
except (FileNotFoundError, ValueError):
    pass

pytestmark = pytest.mark.skipif(
    len(reasons_to_skip) > 0, reason=". ".join(reasons_to_skip)
)

if not reasons_to_skip:
    from solution import (
        PATH_ITERATOR,
        TOP_5_REQUESTS,
        LogEntry,
        build_path_tree,
        cache_result,
        collect_errors_by_type,
        create_analyzer,
        generate_frequent_ips_report,
        load_log_entries,
        parse_log_entry,
    )

VALID_LOG_LINE = '127.0.0.1 - - [10/Oct/2022:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 1541 "http://example.com/start/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
INVALID_LOG_LINE = "This is not a valid log line"
LOG_LINES_FOR_FILE = [
    '89.234.12.3 - - [10/Mar/2023:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 5120 "-" "curl/7.68.0"',
    '10.0.0.1 - - [10/Mar/2023:12:01:15 +0000] "POST /login HTTP/1.1" 404 150 "http://example.com/login" "Mozilla/5.0"',
    "Malformed line here",
    '89.234.12.3 - - [10/Mar/2023:12:02:30 +0000] "GET /static/style.css HTTP/1.1" 200 1024 "http://example.com/index.html" "Mozilla/5.0"',
    '192.168.0.5 - - [10/Mar/2023:12:03:45 +0000] "PUT /api/users/1 HTTP/1.1" 500 50 "-" "PostmanRuntime/7.29.0"',
    '89.234.12.3 - - [10/Mar/2023:12:04:00 +0000] "POST /submit HTTP/1.1" 403 120 "http://example.com/form" "Mozilla/5.0"',
]

TestData = namedtuple("TestData", ["log_entry_200", "log_entry_404", "log_entry_500"])


@pytest.fixture(scope="function")
def log_data():
    data = TestData(
        log_entry_200=LogEntry(
            {
                "ip": "1.1.1.1",
                "timestamp": "_",
                "method": "GET",
                "path": "/",
                "code": 200,
                "response_size": 1000,
                "referer": "-",
                "user_agent": "-",
            }
        ),
        log_entry_404=LogEntry(
            {
                "ip": "2.2.2.2",
                "timestamp": "__",
                "method": "POST",
                "path": "/login",
                "code": 404,
                "response_size": 150,
                "referer": "-",
                "user_agent": "-",
            }
        ),
        log_entry_500=LogEntry(
            {
                "ip": "3.3.3.3",
                "timestamp": "___",
                "method": "PUT",
                "path": "/api",
                "code": 500,
                "response_size": 50,
                "referer": "-",
                "user_agent": "-",
            }
        ),
    )
    return data


@pytest.fixture(scope="module")
def loaded_logs():
    mock_file_content = "\n".join(LOG_LINES_FOR_FILE)
    with patch("builtins.open", mock_open(read_data=mock_file_content)):
        return list(load_log_entries("dummy_path.log"))


def test_parse_log_entry_valid():
    result = parse_log_entry(VALID_LOG_LINE)
    assert result is not None
    assert isinstance(result, dict)
    assert result["ip"] == "127.0.0.1"
    assert result["timestamp"] == "10/Oct/2022:13:55:36 +0000"
    assert result["method"] == "GET"
    assert result["path"] == "/index.html"
    assert result["code"] == 200
    assert result["response_size"] == 1541
    assert result["referer"] == "http://example.com/start/"
    assert result["user_agent"] == "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"


def test_parse_log_entry_invalid():
    assert parse_log_entry(INVALID_LOG_LINE) is None


def test_log_entry_init():
    data = {
        "ip": "127.0.0.1",
        "timestamp": "10/Oct/2022:13:55:36 +0000",
        "method": "GET",
        "path": "/index.html",
        "code": 200,
        "response_size": 1541,
        "referer": "http://example.com/start/",
        "user_agent": "Mozilla/5.0",
    }
    entry = LogEntry(data)
    assert entry.ip == "127.0.0.1"
    assert entry.path == "/index.html"
    assert entry.code == 200
    assert entry.referer == "http://example.com/start/"
    assert entry.user_agent == "Mozilla/5.0"


def test_log_entry_is_error_property(log_data):
    assert not log_data.log_entry_200.is_error, "Код 200 не должен считаться ошибкой"
    assert log_data.log_entry_404.is_error, "Код 404 должен считаться ошибкой"
    assert log_data.log_entry_500.is_error, "Код 500 должен считаться ошибкой"

    entry_302_data = {
        "ip": "4.4.4.4",
        "timestamp": "_",
        "method": "GET",
        "path": "/",
        "code": 302,
        "response_size": 200,
        "referer": "-",
        "user_agent": "-",
    }
    entry_302 = LogEntry(entry_302_data)
    assert not entry_302.is_error, "Код 302 не должен считаться ошибкой"


def test_load_log_entries():
    mock_file_content = "\n".join(LOG_LINES_FOR_FILE)
    with patch("builtins.open", mock_open(read_data=mock_file_content)) as mocked_file:
        entries_iterator = load_log_entries("dummy_path.log")
        entry_list = list(entries_iterator)
        assert len(entry_list) == len(LOG_LINES_FOR_FILE) - 1
        assert all(isinstance(e, LogEntry) for e in entry_list)
        assert entry_list[0].ip == "89.234.12.3"


def test_collect_errors_by_type(log_data):
    errors_dict = {}
    collect_errors_by_type(log_data.log_entry_404, errors_dict)
    assert "client" in errors_dict
    assert len(errors_dict["client"]) == 1
    collect_errors_by_type(log_data.log_entry_500, errors_dict)
    assert "server" in errors_dict
    assert len(errors_dict["server"]) == 1


def test_generate_frequent_ips_report(loaded_logs):
    report = generate_frequent_ips_report(loaded_logs, min_requests=2)
    assert "89.234.12.3" in report
    assert report["89.234.12.3"] == 3
    assert len(report) == 1


def test_functional_constants_hash():
    # Хешируем TOP_5_REQUESTS
    top_5_str = "".join(
        f"{r.method}:{r.path}:{r.response_size}" for r in TOP_5_REQUESTS
    )
    top_5_hash = hashlib.sha256(top_5_str.encode()).hexdigest()

    expected_top_5_hash = (
        "1c070b067b797ec92e1467469ed4e0abfc835b9cbdcfe976cb07b55382ca5742"
    )
    assert top_5_hash == expected_top_5_hash, "Хеш для TOP_5_REQUESTS не совпадает"

    # Хешируем PATH_ITERATOR
    path_list = sorted(list(PATH_ITERATOR))
    path_str = "".join(path_list)
    path_hash = hashlib.sha256(path_str.encode()).hexdigest()

    expected_path_hash = (
        "8efc71346636fa5058306d0907dfb4ddd94714721d05478d6a3179ff2249f05f"
    )
    assert path_hash == expected_path_hash, "Хеш для PATH_ITERATOR не совпадает"


def test_create_analyzer_higher_order_function(loaded_logs):
    post_filter = lambda entry: entry.method == "POST"
    max_size_aggregator = lambda entries: max(
        (e.response_size for e in entries), default=0
    )

    post_max_size_analyzer = create_analyzer(post_filter, max_size_aggregator)
    max_post_size = post_max_size_analyzer(loaded_logs)
    assert max_post_size == 150


def test_build_path_tree():
    log_entries_data = [
        {"path": "/articles/tech/"},
        {"path": "/articles/tech/intro.html"},
        {"path": "/articles/news/"},
        {"path": "/articles/tech/details.html"},
        {"path": "/articles/news/"},
    ]

    def fill_dummy_data(data):
        base = {
            "ip": "1.1.1.1",
            "timestamp": "_",
            "method": "GET",
            "code": 200,
            "response_size": 1,
            "referer": "-",
            "user_agent": "-",
        }
        base.update(data)
        return base

    log_entries = [LogEntry(fill_dummy_data(d)) for d in log_entries_data]

    expected_tree = {
        "articles": {
            "hits": 0,
            "children": {
                "tech": {
                    "hits": 1,
                    "children": {
                        "intro.html": {"hits": 1, "children": {}},
                        "details.html": {"hits": 1, "children": {}},
                    },
                },
                "news": {"hits": 2, "children": {}},
            },
        }
    }
    result_tree = build_path_tree(log_entries)
    assert result_tree == expected_tree


def test_cache_result_decorator():
    mock_func = MagicMock(return_value=100)

    @cache_result
    def decorated(arg):
        return mock_func(arg)

    decorated(1)
    decorated(1)
    mock_func.assert_called_once_with(1)

    decorated(2)
    assert mock_func.call_count == 2