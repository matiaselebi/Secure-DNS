"""Fase 3: traer las consultas de Pi-hole y correrles encima lo nuestro.

La prueba que más importa de todas es la última: que la detección de túneles,
que no se tocó ni una línea, encuentre un túnel mirando consultas que entraron
por Pi-hole. Ese es el objetivo entero de la fase.
"""

import json
import sqlite3
import time
from pathlib import Path

import pytest

from securedns import pihole_consultas as pc
from securedns.config_loader import Config, PiholeConfig
from securedns.logger_db import LoggerDB


def base_pihole(tmp_path, filas) -> str:
    """Una base con la forma de la de Pi-hole. `queries` es una vista allá,
    pero para leer da exactamente lo mismo que una tabla."""
    ruta = tmp_path / "pihole-FTL.db"
    con = sqlite3.connect(ruta)
    con.execute("CREATE TABLE queries (id INTEGER PRIMARY KEY, timestamp INTEGER, "
                "type INTEGER, status INTEGER, domain TEXT, client TEXT, "
                "reply_time REAL)")
    con.executemany("INSERT INTO queries (id, timestamp, type, status, domain, "
                    "client, reply_time) VALUES (?, ?, ?, ?, ?, ?, ?)", filas)
    con.commit()
    con.close()
    return str(ruta)


def config(tmp_path, **extra) -> Config:
    cfg = Config()
    cfg.pihole = PiholeConfig(habilitado=True,
                              marca_de_agua=str(tmp_path / "marca.json"), **extra)
    cfg.logging.db_path = str(tmp_path / "dns_logs.db")
    return cfg


# ---------------------------------------------------------------- traducción

def test_los_estados_bloqueados_y_permitidos_no_se_pisan():
    assert not (pc.BLOQUEADAS & pc.PERMITIDAS)


def test_traduce_bloqueo_y_resolucion():
    filas = [
        {"id": 1, "timestamp": 1_700_000_000, "type": 1, "status": 1,
         "domain": "malo.com", "client": "192.168.1.20", "reply_time": 0.01},
        {"id": 2, "timestamp": 1_700_000_001, "type": 2, "status": 2,
         "domain": "bueno.com", "client": "192.168.1.21", "reply_time": 0.05},
    ]
    salida, raros = pc.traducir(filas)
    assert raros == set()
    assert salida[0]["blocked"] == 1
    assert salida[0]["client_ip"] == "192.168.1.20"
    assert salida[0]["reason"]
    assert salida[1]["blocked"] == 0
    assert salida[1]["reason"] == ""


def test_un_estado_desconocido_no_se_adivina():
    """Contarlo como bloqueo sería inventar; como permitido, esconder."""
    filas = [{"id": 1, "timestamp": 1_700_000_000, "type": 1, "status": 99,
              "domain": "raro.com", "client": "192.168.1.20", "reply_time": 0}]
    salida, raros = pc.traducir(filas)
    assert salida == []
    assert raros == {99}


def test_el_estado_cero_tampoco_se_cuenta():
    """0 es 'todavía sin determinar'. No es ni bloqueo ni resolución."""
    filas = [{"id": 1, "timestamp": 1, "type": 1, "status": 0,
              "domain": "x.com", "client": "c", "reply_time": 0}]
    salida, raros = pc.traducir(filas)
    assert salida == []
    assert raros == {0}


def test_la_hora_se_convierte_a_iso_y_no_queda_en_epoch():
    """Si entrara el epoch crudo, la tabla ordena por texto y todas las filas
    importadas quedarían al final para siempre. Ya pasó una vez."""
    filas = [{"id": 1, "timestamp": 1_700_000_000, "type": 1, "status": 1,
              "domain": "malo.com", "client": "c", "reply_time": 0}]
    salida, _ = pc.traducir(filas)
    assert salida[0]["timestamp"].startswith("2023-")
    assert "T" in salida[0]["timestamp"]


def test_los_tipos_de_consulta_se_traducen_bien():
    """La detección de túneles mira la proporción de TXT y NULL: traducir mal
    esto la deja ciega justo donde tiene que mirar."""
    assert pc.tipo_de(1) == "A"
    assert pc.tipo_de(7) == "TXT"
    assert pc.tipo_de(16) == "HTTPS"
    # Los tipos raros vienen con +100 de corrimiento y no se inventan.
    assert pc.tipo_de(107) == "OTHER"
    assert pc.tipo_de(None) == "OTHER"


def test_la_categoria_sale_de_nuestras_listas_no_de_pihole():
    """Pi-hole sabe que bloqueó; no sabe de qué. Gravity mezcla todo."""
    filas = [{"id": 1, "timestamp": 1, "type": 1, "status": 1,
              "domain": "malo.com", "client": "c", "reply_time": 0}]
    salida, _ = pc.traducir(filas, categoria_de=lambda d: "malware")
    assert salida[0]["category"] == "malware"


def test_las_resueltas_no_llevan_categoria():
    filas = [{"id": 1, "timestamp": 1, "type": 1, "status": 2,
              "domain": "bueno.com", "client": "c", "reply_time": 0}]
    salida, _ = pc.traducir(filas, categoria_de=lambda d: "malware")
    assert salida[0]["category"] == ""


def test_la_cache_de_pihole_queda_marcada_como_cache():
    """Las estadísticas de SecureDNS cuentan los aciertos de caché mirando
    `source = 'cache'`."""
    filas = [{"id": 1, "timestamp": 1, "type": 1, "status": 3,
              "domain": "bueno.com", "client": "c", "reply_time": 0}]
    salida, _ = pc.traducir(filas)
    assert salida[0]["source"] == "cache"


def test_el_padre_se_calcula_al_importar():
    filas = [{"id": 1, "timestamp": 1, "type": 1, "status": 2,
              "domain": "a3f9.tunel.malo.com", "client": "c", "reply_time": 0}]
    salida, _ = pc.traducir(filas)
    assert salida[0]["parent"] == "malo.com"


# ---------------------------------------------------------------- lectura

def test_solo_lectura_de_verdad(tmp_path):
    """No es una convención: con mode=ro SQLite se niega a escribir aunque el
    archivo tenga permiso."""
    ruta = base_pihole(tmp_path, [(1, 1, 1, 1, "malo.com", "c", 0.0)])
    con = pc._conectar(ruta)
    with pytest.raises(sqlite3.OperationalError):
        con.execute("DELETE FROM queries")
    con.close()


def test_lee_solo_lo_nuevo(tmp_path):
    ruta = base_pihole(tmp_path, [
        (1, 1, 1, 1, "a.com", "c", 0.0),
        (2, 2, 1, 1, "b.com", "c", 0.0),
        (3, 3, 1, 1, "c.com", "c", 0.0),
    ])
    filas, ultimo = pc.leer_nuevas(ruta, 1)
    assert [f["domain"] for f in filas] == ["b.com", "c.com"]
    assert ultimo == 3


def test_una_base_que_no_existe_no_rompe(tmp_path):
    filas, ultimo = pc.leer_nuevas(str(tmp_path / "no_existe.db"), 0)
    assert filas == []
    assert ultimo == 0


# ---------------------------------------------------------------- importar

def test_importar_entero(tmp_path):
    ruta = base_pihole(tmp_path, [
        (1, 1_700_000_000, 1, 1, "malo.com", "192.168.1.20", 0.01),
        (2, 1_700_000_001, 2, 2, "bueno.com", "192.168.1.21", 0.05),
    ])
    cfg = config(tmp_path, base_consultas=ruta)
    logger = LoggerDB(cfg.logging.db_path)

    informe = pc.importar(cfg, logger)

    assert informe["ok"]
    assert informe["importadas"] == 2
    con = sqlite3.connect(cfg.logging.db_path)
    filas = con.execute("SELECT domain, client_ip, origen FROM queries").fetchall()
    con.close()
    assert {f[0] for f in filas} == {"malo.com", "bueno.com"}
    # Lo que evita el doble conteo en SecureCenter.
    assert {f[2] for f in filas} == {"pihole"}


def test_no_importa_dos_veces_lo_mismo(tmp_path):
    ruta = base_pihole(tmp_path, [(1, 1_700_000_000, 1, 1, "malo.com", "c", 0.0)])
    cfg = config(tmp_path, base_consultas=ruta)
    logger = LoggerDB(cfg.logging.db_path)

    assert pc.importar(cfg, logger)["importadas"] == 1
    assert pc.importar(cfg, logger)["importadas"] == 0


def test_la_marca_de_agua_queda_guardada(tmp_path):
    ruta = base_pihole(tmp_path, [(7, 1_700_000_000, 1, 1, "malo.com", "c", 0.0)])
    cfg = config(tmp_path, base_consultas=ruta)
    pc.importar(cfg, LoggerDB(cfg.logging.db_path))
    guardado = json.loads(Path(cfg.pihole.marca_de_agua).read_text())
    assert guardado["ultimo_id"] == 7


def test_si_pihole_recrea_su_base_se_vuelve_a_empezar(tmp_path):
    """Sin esta comprobación, una reinstalación de Pi-hole deja la marca
    adelante de todo y no se importa nunca más, en silencio."""
    cfg = config(tmp_path, base_consultas=base_pihole(
        tmp_path, [(500, 1_700_000_000, 1, 1, "viejo.com", "c", 0.0)]))
    logger = LoggerDB(cfg.logging.db_path)
    pc.importar(cfg, logger)
    assert pc.MarcaDeAgua(cfg.pihole.marca_de_agua).leer() == 500

    # Pi-hole arranca de cero: ids chicos otra vez.
    (tmp_path / "pihole-FTL.db").unlink()
    base_pihole(tmp_path, [(1, 1_700_000_100, 1, 1, "nuevo.com", "c", 0.0)])

    informe = pc.importar(cfg, logger)
    assert informe["importadas"] == 1


def test_apagado_no_hace_nada(tmp_path):
    cfg = config(tmp_path, base_consultas=base_pihole(
        tmp_path, [(1, 1, 1, 1, "malo.com", "c", 0.0)]))
    cfg.pihole.habilitado = False
    informe = pc.importar(cfg, LoggerDB(cfg.logging.db_path))
    assert informe["ok"] and informe["salteado"]
    assert informe["importadas"] == 0


def test_base_que_falta_lo_dice_claro(tmp_path):
    cfg = config(tmp_path, base_consultas=str(tmp_path / "no_esta.db"))
    informe = pc.importar(cfg, LoggerDB(cfg.logging.db_path))
    assert not informe["ok"]
    assert "no encuentro" in informe["detalle"]


def test_los_estados_raros_se_informan(tmp_path):
    ruta = base_pihole(tmp_path, [
        (1, 1_700_000_000, 1, 1, "malo.com", "c", 0.0),
        (2, 1_700_000_001, 1, 77, "raro.com", "c", 0.0),
    ])
    cfg = config(tmp_path, base_consultas=ruta)
    informe = pc.importar(cfg, LoggerDB(cfg.logging.db_path))
    assert informe["importadas"] == 1
    assert informe["desconocidos"] == [77]
    # Y la marca igual avanza: si no, ese estado raro frenaría todo para siempre.
    assert informe["ultimo_id"] == 2


# ------------------------------------------------- lo que se salvó de verdad

def test_la_deteccion_de_tuneles_funciona_sobre_consultas_de_pihole(tmp_path):
    """El objetivo entero de la fase 3, en un test.

    `deteccion.py` no se tocó. Lo único que cambió es de dónde salen las
    filas, y encima ahora traen la IP del equipo de la casa que preguntó, que
    antes no existía: el resolutor propio veía una sola máquina.
    """
    ahora = int(time.time())
    filas = []
    # Un túnel: 60 subdominios largos y aleatorios contra el mismo padre,
    # todos TXT, desde el mismo equipo.
    for i in range(60):
        variable = f"{i:04d}" + "k7h3n9q2p5x8z1w4" * 2
        filas.append((i + 1, ahora - 60 + i, 7, 2,
                      f"{variable}.tunel.exfil.com", "192.168.1.55", 0.01))
    ruta = base_pihole(tmp_path, filas)

    cfg = config(tmp_path, base_consultas=ruta)
    logger = LoggerDB(cfg.logging.db_path)
    assert pc.importar(cfg, logger)["importadas"] == 60

    sospechosos = logger.tunneling(horas=24)

    assert sospechosos, "la detección tendría que haber marcado el túnel"
    grupo = sospechosos[0]
    assert grupo["padre"] == "exfil.com"
    # El equipo de la casa, que es lo que Pi-hole aporta y el resolutor propio
    # no podía saber.
    assert grupo["cliente"] == "192.168.1.55"
    assert len(grupo["senales"]) >= 2
