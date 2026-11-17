"""
数据持久化模块 v2.4
使用 SQLAlchemy ORM 提供数据库抽象层，支持 SQLite（开发/测试）
和 PostgreSQL（生产环境）。
向后兼容原有的 sqlite3 直接操作接口。
"""

from __future__ import annotations

import json
import os
import time
import logging
from pathlib import Path
from typing import List, Dict, Optional, Any, TypeVar, Generic, Literal
from contextlib import contextmanager

from sqlalchemy import (
    create_engine,
    text as sqlalchemy_text,
    Column, Integer, String, Text, Float, DateTime, Index,
    func as sql_func,
)
from sqlalchemy.orm import (
    declarative_base,
    sessionmaker,
    Session,
    Mapped,
    mapped_column,
)
from sqlalchemy.engine import Engine

Base = declarative_base()

T = TypeVar("T")


# ============================================================
# 数据库配置（从环境变量读取，支持 SQLite/PostgreSQL 切换）
# ============================================================

DATABASE_CONFIG: Dict[str, Any] = {
    "engine": os.environ.get("DB_ENGINE", "sqlite").lower(),  # "sqlite" | "postgres"
    "sqlite_path": os.environ.get("DB_SQLITE_PATH", "./data/assessment.db"),
    "postgres_host": os.environ.get("DB_POSTGRES_HOST", "localhost"),
    "postgres_port": int(os.environ.get("DB_POSTGRES_PORT", "5432")),
    "postgres_user": os.environ.get("DB_POSTGRES_USER", "postgres"),
    "postgres_password": os.environ.get("DB_POSTGRES_PASSWORD", "__REQUIRED__"),
    "postgres_db": os.environ.get("DB_POSTGRES_DB", "assessment"),
    "pool_size": int(os.environ.get("DB_POOL_SIZE", "10")),
    "max_overflow": int(os.environ.get("DB_MAX_OVERFLOW", "20")),
    "pool_timeout": int(os.environ.get("DB_POOL_TIMEOUT", "30")),
    "pool_recycle": int(os.environ.get("DB_POOL_RECYCLE", "1800")),
    "echo": os.environ.get("DB_ECHO", "false").lower() == "true",
}


def _init_db_logging() -> None:
    """初始化数据库日志管理器：设置 SQLAlchemy 日志级别，避免打印敏感信息。

    - sqlalchemy.engine / sqlalchemy.pool 默认为 WARNING
    - 仅在 DB_ECHO=true 时启用 INFO 级别
    """
    root_logger = logging.getLogger("database")
    if not root_logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("[%(asctime)s][%(levelname)s] %(message)s")
        )
        root_logger.addHandler(handler)
    root_logger.setLevel(logging.INFO if DATABASE_CONFIG["echo"] else logging.WARNING)

    # 屏蔽 SQLAlchemy 内部敏感日志（连接字符串、密码等）
    for sub in ("sqlalchemy.engine", "sqlalchemy.pool", "sqlalchemy.orm"):
        logging.getLogger(sub).setLevel(logging.WARNING)

    root_logger.info("数据库日志管理器已初始化")


def build_db_url() -> str:
    """根据 DATABASE_CONFIG 构造 SQLAlchemy 数据库 URL。

    - SQLite: ``sqlite:///./data/assessment.db``（使用时需要 check_same_thread=False）
    - PostgreSQL: ``postgresql://user:password@host:port/db``

    若 PostgreSQL 密码为 ``__REQUIRED__``，打印警告并自动降级到 SQLite。
    """
    engine = DATABASE_CONFIG["engine"]

    if engine == "postgres":
        pwd = DATABASE_CONFIG["postgres_password"]
        if pwd == "__REQUIRED__":
            print(
                "[WARN] PostgreSQL 密码未配置（DB_POSTGRES_PASSWORD=__REQUIRED__），"
                "已自动降级到 SQLite 数据库"
            )
            return f"sqlite:///{DATABASE_CONFIG['sqlite_path']}"
        return (
            f"postgresql://{DATABASE_CONFIG['postgres_user']}:"
            f"{pwd}@{DATABASE_CONFIG['postgres_host']}:"
            f"{DATABASE_CONFIG['postgres_port']}/{DATABASE_CONFIG['postgres_db']}"
        )

    # 默认 / sqlite
    return f"sqlite:///{DATABASE_CONFIG['sqlite_path']}"


def _mask_db_url(url: str) -> str:
    """将数据库 URL 中的密码部分掩码为 ``***`` 后返回。"""
    if "://" not in url:
        return url
    head, body = url.split("://", 1)
    # 形如 user:pwd@host:port/db  →  user:***@host:port/db
    if "@" in body and ":" in body.split("@", 1)[0]:
        user_part, rest = body.split("@", 1)
        if ":" in user_part:
            user, _ = user_part.split(":", 1)
            return f"{head}://{user}:***@{rest}"
    return url


# 模块级别调用一次：初始化数据库日志管理器
_init_db_logging()


# ============================================================
# SQLAlchemy ORM 模型定义
# ============================================================

class ScanRecordModel(Base):
    """扫描记录 ORM 模型"""
    __tablename__ = "scan_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_url: Mapped[str] = mapped_column(String(512), nullable=False)
    cve_id: Mapped[str] = mapped_column(String(64), nullable=False)
    vuln_name: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    status: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    risk_level: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    leaked_data: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    execution_log: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    analysis_report: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    timestamp: Mapped[int] = mapped_column(Integer, nullable=False)
    duration: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[str] = mapped_column(
        DateTime, server_default=sql_func.now()
    )

    __table_args__ = (
        Index("idx_scan_target", "target_url", "timestamp"),
        Index("idx_scan_cve", "cve_id", "timestamp"),
    )


class PatchRecordModel(Base):
    """补丁记录 ORM 模型"""
    __tablename__ = "patch_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cve_id: Mapped[str] = mapped_column(String(64), nullable=False)
    patch_title: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    patch_type: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    status: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    lines_added: Mapped[int] = mapped_column(Integer, default=0)
    verification_result: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    timestamp: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[str] = mapped_column(
        DateTime, server_default=sql_func.now()
    )


class AdversarialRecordModel(Base):
    """对抗记录 ORM 模型"""
    __tablename__ = "adversarial_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_url: Mapped[str] = mapped_column(String(512), nullable=False)
    max_rounds: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    red_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    blue_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    winner: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    vulnerability_stats: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    duration: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    timestamp: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[str] = mapped_column(
        DateTime, server_default=sql_func.now()
    )


class ModelEvalStatsModel(Base):
    """模型评估统计 ORM 模型"""
    __tablename__ = "model_eval_stats"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    eval_mode: Mapped[str] = mapped_column(String(32), nullable=False)
    model_name: Mapped[str] = mapped_column(String(64), nullable=False)
    total_score: Mapped[int] = mapped_column(Integer, default=0)
    innovation_score: Mapped[int] = mapped_column(Integer, default=0)
    practicality_score: Mapped[int] = mapped_column(Integer, default=0)
    technical_difficulty_score: Mapped[int] = mapped_column(Integer, default=0)
    security_score: Mapped[int] = mapped_column(Integer, default=0)
    documentation_score: Mapped[int] = mapped_column(Integer, default=0)
    ai_bonus_score: Mapped[int] = mapped_column(Integer, default=0)
    rank: Mapped[Optional[str]] = mapped_column(String(8), nullable=True)
    timestamp: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[str] = mapped_column(
        DateTime, server_default=sql_func.now()
    )

    __table_args__ = (
        Index("idx_model_eval_mode", "eval_mode", "timestamp"),
    )


# ============================================================
# SQLAlchemy 数据库管理器
# ============================================================

class SQLAlchemyDB:
    """基于 SQLAlchemy 的数据库会话管理器（支持 SQLite/PostgreSQL）"""

    _instance: Optional["SQLAlchemyDB"] = None

    def __init__(self, db_url: str = "sqlite:///./data/assessment.db"):
        self.db_url = db_url
        # 自动识别引擎类型：根据 URL 前缀判断
        if db_url.startswith("postgresql") or db_url.startswith("postgres+"):
            self.engine_type: Literal["sqlite", "postgres"] = "postgres"
        else:
            self.engine_type = "sqlite"

        # 连接池配置：仅在 postgres 模式下启用，sqlite 使用占位
        self.pool_info: Dict[str, Any] = {
            "engine_type": self.engine_type,
            "pool_size": DATABASE_CONFIG["pool_size"],
            "max_overflow": DATABASE_CONFIG["max_overflow"],
            "pool_timeout": DATABASE_CONFIG["pool_timeout"],
            "pool_recycle": DATABASE_CONFIG["pool_recycle"],
        }

        if self.engine_type == "sqlite":
            # SQLite URL 需要 check_same_thread=False 以支持多线程访问
            self._engine: Engine = create_engine(
                db_url,
                connect_args={"check_same_thread": False},
                echo=DATABASE_CONFIG["echo"],
            )
        else:
            # PostgreSQL：启用连接池
            self._engine = create_engine(
                db_url,
                pool_size=DATABASE_CONFIG["pool_size"],
                max_overflow=DATABASE_CONFIG["max_overflow"],
                pool_timeout=DATABASE_CONFIG["pool_timeout"],
                pool_recycle=DATABASE_CONFIG["pool_recycle"],
                pool_pre_ping=True,
                echo=DATABASE_CONFIG["echo"],
            )
        self._session_factory = sessionmaker(bind=self._engine)

    @classmethod
    def get_instance(cls, db_url: str = "") -> "SQLAlchemyDB":
        if cls._instance is None:
            # 默认使用 DATABASE_CONFIG 构造 URL
            effective_url = db_url if db_url else build_db_url()
            cls._instance = cls(effective_url)
            print(
                f"[Database] 使用 {cls._instance.engine_type} 数据库，"
                f"URL: {_mask_db_url(cls._instance.db_url)}"
            )
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        cls._instance = None

    def ping(self) -> Dict[str, Any]:
        """测试数据库连接是否可用（执行 ``SELECT 1``）。

        返回结构：
        ``{available: bool, latency_ms: int, engine: str, error: str | None}``
        """
        start = time.perf_counter()
        error_msg: Optional[str] = None
        available = False
        try:
            with self._engine.connect() as conn:
                conn.execute(sqlalchemy_text("SELECT 1"))
            available = True
        except Exception as exc:  # noqa: BLE001
            error_msg = str(exc)
        latency_ms = int((time.perf_counter() - start) * 1000)
        return {
            "available": available,
            "latency_ms": latency_ms,
            "engine": self.engine_type,
            "error": error_msg,
        }

    def get_pool_stats(self) -> Dict[str, Any]:
        """获取连接池统计信息。

        - PostgreSQL：读取 pool 内部的 checked_in/checked_out/overflow
        - SQLite：返回占位值（SQLite 不使用连接池）
        """
        pool = getattr(self._engine, "pool", None)
        if self.engine_type != "postgres" or pool is None:
            return {
                "engine_type": self.engine_type,
                "pool_size": self.pool_info["pool_size"],
                "max_overflow": self.pool_info["max_overflow"],
                "pool_timeout": self.pool_info["pool_timeout"],
                "pool_recycle": self.pool_info["pool_recycle"],
                "checked_in": 0,
                "checked_out": 0,
                "overflow": 0,
            }
        # 读取 SQLAlchemy 连接池私有属性
        _pool = pool
        checked_in = len(getattr(_pool, "_pool", []))
        checked_out = getattr(_pool, "_checked_out", 0)
        overflow = getattr(_pool, "_overflow", 0)
        # 兼容不同版本：_checked_out / _overflow 可能是 int 或 deque
        if hasattr(checked_out, "__len__"):
            checked_out = len(checked_out)
        if hasattr(overflow, "__len__"):
            overflow = len(overflow)
        return {
            "engine_type": self.engine_type,
            "pool_size": self.pool_info["pool_size"],
            "max_overflow": self.pool_info["max_overflow"],
            "pool_timeout": self.pool_info["pool_timeout"],
            "pool_recycle": self.pool_info["pool_recycle"],
            "checked_in": int(checked_in),
            "checked_out": int(checked_out),
            "overflow": int(overflow),
        }

    def create_tables(self) -> None:
        """创建所有表结构"""
        Base.metadata.create_all(self._engine)

    @contextmanager
    def get_session(self) -> Session:
        """获取数据库会话的上下文管理器"""
        session = self._session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    # ========== 扫描记录操作 ==========

    def save_scan_record(self, record: "ScanRecord") -> int:
        """保存扫描记录（ORM 模式）"""
        with self.get_session() as session:
            model = ScanRecordModel(
                target_url=record.target_url,
                cve_id=record.cve_id,
                vuln_name=record.vuln_name,
                status=record.status,
                risk_level=record.risk_level,
                leaked_data=record.leaked_data,
                execution_log=record.execution_log,
                analysis_report=record.analysis_report,
                timestamp=record.timestamp or int(time.time()),
                duration=record.duration,
            )
            session.add(model)
            session.flush()
            return model.id

    def get_scan_history(
        self,
        target_url: Optional[str] = None,
        cve_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """获取扫描历史（ORM 模式）"""
        with self.get_session() as session:
            query = session.query(ScanRecordModel)
            if target_url:
                query = query.filter(ScanRecordModel.target_url == target_url)
            if cve_id:
                query = query.filter(ScanRecordModel.cve_id == cve_id)
            results = query.order_by(
                ScanRecordModel.timestamp.desc()
            ).limit(limit).all()
            return [_model_to_dict(r) for r in results]

    def get_scan_stats(
        self, target_url: Optional[str] = None
    ) -> Dict[str, Any]:
        """获取扫描统计（ORM 模式）"""
        with self.get_session() as session:
            query = session.query(ScanRecordModel)
            if target_url:
                query = query.filter(ScanRecordModel.target_url == target_url)

            total = query.count()
            successes = query.filter(
                ScanRecordModel.status == "success"
            ).count()
            success_rate = round(successes / total, 2) if total else 0

            cve_rows = (
                session.query(
                    ScanRecordModel.cve_id,
                    ScanRecordModel.status,
                    sql_func.count(ScanRecordModel.id).label("count"),
                )
                .filter(
                    ScanRecordModel.target_url == target_url
                    if target_url else True
                )
                .group_by(ScanRecordModel.cve_id, ScanRecordModel.status)
                .all()
            )

            return {
                "total_scans": total,
                "successful_scans": successes,
                "success_rate": success_rate,
                "by_cve": [
                    {"cve_id": r.cve_id, "status": r.status, "count": r.count}
                    for r in cve_rows
                ],
            }

    # ========== 补丁记录操作 ==========

    def save_patch_record(self, record: "PatchRecord") -> int:
        """保存补丁记录（ORM 模式）"""
        with self.get_session() as session:
            model = PatchRecordModel(
                cve_id=record.cve_id,
                patch_title=record.patch_title,
                patch_type=record.patch_type,
                status=record.status,
                lines_added=record.lines_added,
                verification_result=record.verification_result,
                timestamp=record.timestamp or int(time.time()),
            )
            session.add(model)
            session.flush()
            return model.id

    def get_patch_history(self, limit: int = 20) -> List[Dict[str, Any]]:
        """获取补丁历史（ORM 模式）"""
        with self.get_session() as session:
            results = (
                session.query(PatchRecordModel)
                .order_by(PatchRecordModel.timestamp.desc())
                .limit(limit)
                .all()
            )
            return [_model_to_dict(r) for r in results]

    # ========== 对抗记录操作 ==========

    def save_adversarial_record(self, record: "AdversarialRecord") -> int:
        """保存对抗记录（ORM 模式）"""
        with self.get_session() as session:
            model = AdversarialRecordModel(
                target_url=record.target_url,
                max_rounds=record.max_rounds,
                red_score=record.red_score,
                blue_score=record.blue_score,
                winner=record.winner,
                vulnerability_stats=record.vulnerability_stats,
                duration=record.duration,
                timestamp=record.timestamp or int(time.time()),
            )
            session.add(model)
            session.flush()
            return model.id

    def get_adversarial_history(self, limit: int = 20) -> List[Dict[str, Any]]:
        """获取对抗历史（ORM 模式）"""
        with self.get_session() as session:
            results = (
                session.query(AdversarialRecordModel)
                .order_by(AdversarialRecordModel.timestamp.desc())
                .limit(limit)
                .all()
            )
            return [_model_to_dict(r) for r in results]

    # ========== 模型评估统计操作 ==========

    def save_model_eval_stats(self, record: "ModelEvalStats") -> int:
        """保存模型评估统计（ORM 模式）"""
        with self.get_session() as session:
            model = ModelEvalStatsModel(
                eval_mode=record.eval_mode,
                model_name=record.model_name,
                total_score=record.total_score,
                innovation_score=record.innovation_score,
                practicality_score=record.practicality_score,
                technical_difficulty_score=record.technical_difficulty_score,
                security_score=record.security_score,
                documentation_score=record.documentation_score,
                ai_bonus_score=record.ai_bonus_score,
                rank=record.rank,
                timestamp=record.timestamp or int(time.time()),
            )
            session.add(model)
            session.flush()
            return model.id

    def get_model_eval_history(
        self,
        eval_mode: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """获取模型评估历史（ORM 模式）"""
        with self.get_session() as session:
            query = session.query(ModelEvalStatsModel)
            if eval_mode:
                query = query.filter(ModelEvalStatsModel.eval_mode == eval_mode)
            results = (
                query.order_by(ModelEvalStatsModel.timestamp.desc())
                .limit(limit)
                .all()
            )
            return [_model_to_dict(r) for r in results]

    def get_model_eval_best(
        self, eval_mode: str = "full"
    ) -> Optional[Dict[str, Any]]:
        """获取某评估模式下的最高分记录（ORM 模式）"""
        with self.get_session() as session:
            result = (
                session.query(ModelEvalStatsModel)
                .filter(ModelEvalStatsModel.eval_mode == eval_mode)
                .order_by(ModelEvalStatsModel.total_score.desc())
                .first()
            )
            return _model_to_dict(result) if result else None


def _model_to_dict(model: Any) -> Dict[str, Any]:
    """将 SQLAlchemy 模型对象转换为字典"""
    return {
        c.name: getattr(model, c.name)
        for c in model.__table__.columns
    }


# ============================================================
# 原有 sqlite3 兼容层（向后兼容）
# 代码保持不变，仅在 Database 类中新增 ORM 路由开关
# ============================================================

import sqlite3
from dataclasses import dataclass, asdict


@dataclass
class ScanRecord:
    """扫描记录"""
    id: Optional[int] = None
    target_url: str = ""
    cve_id: str = ""
    vuln_name: str = ""
    status: str = ""
    risk_level: str = ""
    leaked_data: Optional[str] = None
    execution_log: str = ""
    analysis_report: str = ""
    timestamp: int = 0
    duration: float = 0.0


@dataclass
class PatchRecord:
    """补丁记录"""
    id: Optional[int] = None
    cve_id: str = ""
    patch_title: str = ""
    patch_type: str = ""
    status: str = ""
    lines_added: int = 0
    verification_result: str = ""
    timestamp: int = 0


@dataclass
class AdversarialRecord:
    """对抗记录"""
    id: Optional[int] = None
    target_url: str = ""
    max_rounds: int = 0
    red_score: int = 0
    blue_score: int = 0
    winner: str = ""
    vulnerability_stats: str = ""
    duration: float = 0.0
    timestamp: int = 0


@dataclass
class ModelEvalStats:
    """模型评估统计记录"""
    id: Optional[int] = None
    eval_mode: str = ""
    model_name: str = ""
    total_score: int = 0
    innovation_score: int = 0
    practicality_score: int = 0
    technical_difficulty_score: int = 0
    security_score: int = 0
    documentation_score: int = 0
    ai_bonus_score: int = 0
    rank: str = ""
    timestamp: int = 0


class Database:
    """数据库管理类 v2.4
    支持双模式切换：
    - use_orm=True: 使用 SQLAlchemy ORM（推荐，生产环境使用）
    - use_orm=False: 使用原有 sqlite3 直接操作（向后兼容）
    """

    _instance: Optional["Database"] = None
    _shared_memory_conn: Optional[sqlite3.Connection] = None

    def __init__(
        self,
        db_path: str = "./data/assessment.db",
        use_orm: bool = True,
    ):
        self.db_path_str = db_path
        self.use_orm = use_orm
        self.is_in_memory = db_path == ":memory:"

        if use_orm:
            # SQLAlchemy 模式（推荐）
            url = (
                "sqlite:///./data/assessment.db"
                if db_path == "./data/assessment.db"
                else f"sqlite:///{db_path}" if not db_path.startswith("sqlite")
                else db_path
            )
            self._orm_db = SQLAlchemyDB.get_instance(url)
            self._orm_db.create_tables()
        else:
            # 原有 sqlite3 兼容模式
            self._orm_db = None
            if self.is_in_memory:
                if Database._shared_memory_conn is None:
                    Database._shared_memory_conn = sqlite3.connect(
                        ":memory:", check_same_thread=False
                    )
                    Database._shared_memory_conn.row_factory = sqlite3.Row
                    Database._shared_memory_conn.execute(
                        "PRAGMA journal_mode = MEMORY;"
                    )
                    Database._shared_memory_conn.execute(
                        "PRAGMA foreign_keys = ON;"
                    )
                    self._init_db_with_conn(Database._shared_memory_conn)
                    Database._shared_memory_conn.commit()
            else:
                self.db_path = Path(db_path)
                try:
                    self.db_path.parent.mkdir(parents=True, exist_ok=True)
                except (OSError, PermissionError) as e:
                    print(
                        "[WARN] 无法创建数据库目录 %s：%s，降级为临时文件"
                        % (str(self.db_path.parent), e)
                    )
                    self.db_path = Path(db_path)
                self._init_db()

    @classmethod
    def get_instance(
        cls, db_path: str = "./data/assessment.db", use_orm: bool = True
    ) -> "Database":
        if cls._instance is None:
            cls._instance = cls(db_path, use_orm)
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        cls._instance = None
        cls._shared_memory_conn = None
        SQLAlchemyDB.reset_instance()

    @contextmanager
    def _get_conn(self):
        if self.is_in_memory:
            conn = Database._shared_memory_conn
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
        else:
            conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
            conn.row_factory = sqlite3.Row
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    def _init_db_with_conn(self, conn: sqlite3.Connection) -> None:
        cursor = conn.cursor()
        self._create_tables(cursor)

    def _init_db(self):
        with self._get_conn() as conn:
            cursor = conn.cursor()
            self._create_tables(cursor)

    def _create_tables(self, cursor: sqlite3.Cursor) -> None:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL,
                cve_id TEXT NOT NULL,
                vuln_name TEXT,
                status TEXT,
                risk_level TEXT,
                leaked_data TEXT,
                execution_log TEXT,
                analysis_report TEXT,
                timestamp INTEGER,
                duration REAL DEFAULT 0.0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS patch_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT NOT NULL,
                patch_title TEXT,
                patch_type TEXT,
                status TEXT,
                lines_added INTEGER DEFAULT 0,
                verification_result TEXT,
                timestamp INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS adversarial_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL,
                max_rounds INTEGER,
                red_score INTEGER,
                blue_score INTEGER,
                winner TEXT,
                vulnerability_stats TEXT,
                duration REAL,
                timestamp INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS model_eval_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                eval_mode TEXT NOT NULL,
                model_name TEXT NOT NULL,
                total_score INTEGER DEFAULT 0,
                innovation_score INTEGER DEFAULT 0,
                practicality_score INTEGER DEFAULT 0,
                technical_difficulty_score INTEGER DEFAULT 0,
                security_score INTEGER DEFAULT 0,
                documentation_score INTEGER DEFAULT 0,
                ai_bonus_score INTEGER DEFAULT 0,
                rank TEXT,
                timestamp INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_scan_target "
            "ON scan_records(target_url, timestamp)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_scan_cve "
            "ON scan_records(cve_id, timestamp)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_model_eval_mode "
            "ON model_eval_stats(eval_mode, timestamp)"
        )

    # ========== ORM 路由方法（use_orm=True 时使用）==========

    def _orm_save_scan(self, record: ScanRecord) -> int:
        return self._orm_db.save_scan_record(record)

    def _orm_get_scan_history(
        self, target_url: Optional[str] = None,
        cve_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        return self._orm_db.get_scan_history(target_url, cve_id, limit)

    def _orm_get_scan_stats(
        self, target_url: Optional[str] = None,
    ) -> Dict[str, Any]:
        return self._orm_db.get_scan_stats(target_url)

    def _orm_save_patch(self, record: PatchRecord) -> int:
        return self._orm_db.save_patch_record(record)

    def _orm_get_patch_history(self, limit: int = 20) -> List[Dict[str, Any]]:
        return self._orm_db.get_patch_history(limit)

    def _orm_save_adversarial(self, record: AdversarialRecord) -> int:
        return self._orm_db.save_adversarial_record(record)

    def _orm_get_adversarial_history(self, limit: int = 20) -> List[Dict[str, Any]]:
        return self._orm_db.get_adversarial_history(limit)

    def _orm_save_eval(self, record: ModelEvalStats) -> int:
        return self._orm_db.save_model_eval_stats(record)

    def _orm_get_eval_history(
        self,
        eval_mode: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        return self._orm_db.get_model_eval_history(eval_mode, limit)

    def _orm_get_eval_best(
        self, eval_mode: str = "full",
    ) -> Optional[Dict[str, Any]]:
        return self._orm_db.get_model_eval_best(eval_mode)

    # ========== sqlite3 兼容实现（use_orm=False 或未实现时回退）==========

    def save_scan_record(self, record: ScanRecord) -> int:
        if self.use_orm and self._orm_db:
            return self._orm_save_scan(record)
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO scan_records
                (target_url, cve_id, vuln_name, status, risk_level,
                 leaked_data, execution_log, analysis_report, timestamp, duration)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                record.target_url, record.cve_id, record.vuln_name,
                record.status, record.risk_level, record.leaked_data,
                record.execution_log, record.analysis_report,
                record.timestamp or int(time.time()), record.duration,
            ))
            return cursor.lastrowid or 0

    def save_batch_scan_records(self, records: List[ScanRecord]) -> int:
        count = 0
        for record in records:
            if self.save_scan_record(record):
                count += 1
        return count

    def get_scan_history(
        self,
        target_url: Optional[str] = None,
        cve_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        if self.use_orm and self._orm_db:
            return self._orm_get_scan_history(target_url, cve_id, limit)
        query = "SELECT * FROM scan_records WHERE 1=1"
        params = []
        if target_url:
            query += " AND target_url = ?"
            params.append(target_url)
        if cve_id:
            query += " AND cve_id = ?"
            params.append(cve_id)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def get_scan_stats(
        self, target_url: Optional[str] = None,
    ) -> Dict[str, Any]:
        if self.use_orm and self._orm_db:
            return self._orm_get_scan_stats(target_url)
        where_clause = "WHERE 1=1"
        params = []
        if target_url:
            where_clause += " AND target_url = ?"
            params.append(target_url)
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                SELECT COUNT(*) as total,
                       SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) as successes
                FROM scan_records {where_clause}
            """, params)
            row = cursor.fetchone()
            total = row["total"] or 0
            successes = row["successes"] or 0
            cursor.execute(f"""
                SELECT cve_id, status, COUNT(*) as count
                FROM scan_records {where_clause}
                GROUP BY cve_id, status
            """, params)
            cve_stats = cursor.fetchall()
            return {
                "total_scans": total,
                "successful_scans": successes,
                "success_rate": round(successes / total, 2) if total else 0,
                "by_cve": [dict(r) for r in cve_stats],
            }

    def save_patch_record(self, record: PatchRecord) -> int:
        if self.use_orm and self._orm_db:
            return self._orm_save_patch(record)
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO patch_records
                (cve_id, patch_title, patch_type, status, lines_added,
                 verification_result, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                record.cve_id, record.patch_title, record.patch_type,
                record.status, record.lines_added, record.verification_result,
                record.timestamp or int(time.time()),
            ))
            return cursor.lastrowid or 0

    def get_patch_history(self, limit: int = 20) -> List[Dict[str, Any]]:
        if self.use_orm and self._orm_db:
            return self._orm_get_patch_history(limit)
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM patch_records "
                "ORDER BY timestamp DESC LIMIT ?", (limit,)
            )
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def save_adversarial_record(self, record: AdversarialRecord) -> int:
        if self.use_orm and self._orm_db:
            return self._orm_save_adversarial(record)
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO adversarial_records
                (target_url, max_rounds, red_score, blue_score, winner,
                 vulnerability_stats, duration, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                record.target_url, record.max_rounds, record.red_score,
                record.blue_score, record.winner, record.vulnerability_stats,
                record.duration, record.timestamp or int(time.time()),
            ))
            return cursor.lastrowid or 0

    def get_adversarial_history(self, limit: int = 20) -> List[Dict[str, Any]]:
        if self.use_orm and self._orm_db:
            return self._orm_get_adversarial_history(limit)
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM adversarial_records "
                "ORDER BY timestamp DESC LIMIT ?", (limit,)
            )
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def save_model_eval_stats(self, record: ModelEvalStats) -> int:
        if self.use_orm and self._orm_db:
            return self._orm_save_eval(record)
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO model_eval_stats
                (eval_mode, model_name, total_score, innovation_score,
                 practicality_score, technical_difficulty_score, security_score,
                 documentation_score, ai_bonus_score, rank, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                record.eval_mode, record.model_name, record.total_score,
                record.innovation_score, record.practicality_score,
                record.technical_difficulty_score, record.security_score,
                record.documentation_score, record.ai_bonus_score,
                record.rank, record.timestamp or int(time.time()),
            ))
            return cursor.lastrowid or 0

    def get_model_eval_history(
        self,
        eval_mode: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        if self.use_orm and self._orm_db:
            return self._orm_get_eval_history(eval_mode, limit)
        query = "SELECT * FROM model_eval_stats WHERE 1=1"
        params = []
        if eval_mode:
            query += " AND eval_mode = ?"
            params.append(eval_mode)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def get_model_eval_best(
        self, eval_mode: str = "full",
    ) -> Optional[Dict[str, Any]]:
        if self.use_orm and self._orm_db:
            return self._orm_get_eval_best(eval_mode)
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM model_eval_stats
                WHERE eval_mode = ?
                ORDER BY total_score DESC LIMIT 1
            """, (eval_mode,))
            row = cursor.fetchone()
            return dict(row) if row else None
