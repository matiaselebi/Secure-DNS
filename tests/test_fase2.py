"""Fase 2: detección de tunneling por DNS y de actividad anómala.

La mitad de estos tests son de FALSOS POSITIVOS, y son los que importan. Un
detector que marca todo no sirve: se apaga a la semana. Cada señal por separado
tiene explicaciones inocentes (un CDN genera muchos nombres distintos, un hash
tiene entropía alta, un sistema antispam usa TXT), así que lo que hay que
probar no es solo que encuentre un túnel, sino que NO marque la navegación
normal, ni un CDN, ni un equipo que estaba apagado.
"""

import socket
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from securedns.blocklist import Allowlist, Blocklist  # noqa: E402
from securedns.dashboard import build_dashboard_server  # noqa: E402
from securedns.deteccion import (  # noqa: E402
    dominio_padre,
    entropia,
    evaluar_actividad,
    evaluar_grupo,
    parte_variable,
)
from securedns.dns_server import ThreatIntelResolver  # noqa: E402
from securedns.logger_db import LoggerDB  # noqa: E402


# ------------------------------------------------------ dominio padre


def test_el_padre_son_las_dos_ultimas_etiquetas():
    assert dominio_padre("a3f9.tunel.atacante.com") == "atacante.com"
    assert dominio_padre("www.google.com") == "google.com"
    assert dominio_padre("ejemplo.com") == "ejemplo.com"


def test_los_dominios_argentinos_no_se_juntan_todos():
    """Sin contemplar los sufijos de dos niveles, "las dos últimas etiquetas"
    de ejemplo.com.ar da "com.ar", y TODOS los sitios argentinos quedarían
    agrupados bajo un mismo padre. Eso solo no sería un detalle: sería un falso
    positivo gigante, porque ese grupo tendría miles de nombres distintos."""
    assert dominio_padre("www.mercadolibre.com.ar") == "mercadolibre.com.ar"
    assert dominio_padre("afip.gob.ar") == "afip.gob.ar"
    assert dominio_padre("algo.co.uk") == "algo.co.uk"
    assert dominio_padre("sub.dominio.com.br") == "dominio.com.br"


def test_el_padre_no_se_rompe_con_basura():
    assert dominio_padre("") == ""
    assert dominio_padre("localhost") == "localhost"
    assert dominio_padre("...") == ""


def test_la_parte_variable_saca_el_padre():
    """Medir el nombre entero mezclaría el largo del dominio del atacante con
    el de los datos, que es justo lo que se quiere separar."""
    assert parte_variable("a3f9b2.tunel.malo.com", "malo.com") == "a3f9b2.tunel"
    assert parte_variable("malo.com", "malo.com") == ""


# --------------------------------------------------------- entropía


def test_la_entropia_distingue_palabras_de_datos_codificados():
    palabra = entropia("mercadolibre")
    codificado = entropia("k7x2m9qz4bv8ntr3ws6ydh5jfp1ga0ce")
    assert codificado > palabra
    assert codificado > 4.0


def test_la_entropia_de_algo_repetido_es_cero():
    assert entropia("aaaaaaaa") == 0.0
    assert entropia("") == 0.0


def test_los_puntos_no_cuentan():
    """Los separadores son del protocolo, no de los datos."""
    assert entropia("ab.ab") == pytest.approx(entropia("abab"))


# ------------------------------------------------ evaluación de grupos


def _grupo(**kw):
    base = {
        "cliente": "192.168.1.20", "padre": "algo.com", "total": 500,
        "distintos": 480, "tipos_de_datos": 0, "largo_promedio": 40.0,
        "entropia_promedio": 4.4,
    }
    base.update(kw)
    return base


def test_un_tunel_de_manual_se_marca():
    resultado = evaluar_grupo(_grupo(tipos_de_datos=450))
    assert resultado["sospechoso"] is True
    assert len(resultado["senales"]) >= 3


def test_el_hallazgo_dice_por_que():
    """Lo que hace útil a una detección es poder leer el motivo y discutirlo.
    Un "sospechoso: sí" pelado no se puede auditar."""
    resultado = evaluar_grupo(_grupo(tipos_de_datos=450))
    texto = " ".join(resultado["senales"])
    assert "nombres distintos" in texto
    assert "entropía" in texto
    assert "TXT" in texto


def test_pocas_consultas_no_son_evidencia_de_nada():
    """Cualquier navegación genera un puñado de nombres distintos contra un
    mismo dominio. Sin volumen no hay caso."""
    resultado = evaluar_grupo(_grupo(total=10, distintos=10))
    assert resultado["sospechoso"] is False
    assert resultado["senales"] == []


def test_navegacion_normal_no_se_marca():
    """Entrar muchas veces al mismo sitio: mucho volumen, pocos nombres
    distintos, nombres cortos y con forma de palabra."""
    resultado = evaluar_grupo(_grupo(
        padre="google.com", total=800, distintos=6,
        largo_promedio=4.0, entropia_promedio=2.4, tipos_de_datos=0,
    ))
    assert resultado["sospechoso"] is False


def test_un_cdn_no_se_marca_solo_por_tener_muchos_nombres():
    """Este es el falso positivo más obvio: un CDN genera montones de
    subdominios distintos. Pero son cortos y legibles, así que junta una sola
    señal y no alcanza."""
    resultado = evaluar_grupo(_grupo(
        padre="akamaiedge.net", total=600, distintos=590,
        largo_promedio=12.0, entropia_promedio=3.1, tipos_de_datos=0,
    ))
    assert len(resultado["senales"]) == 1
    assert resultado["sospechoso"] is False


def test_hashes_largos_solos_tampoco_alcanzan():
    """Nombres largos y con entropía alta pero que se repiten (un identificador
    de sesión que se consulta muchas veces) no son un túnel: un túnel no
    repite, porque cada consulta lleva datos nuevos."""
    resultado = evaluar_grupo(_grupo(
        total=500, distintos=20, largo_promedio=40.0,
        entropia_promedio=4.4, tipos_de_datos=0,
    ))
    assert "nombres distintos" not in " ".join(resultado["senales"])
    # Junta largo y entropía, que son dos señales: se marca, y está bien que
    # se marque, porque 20 nombres de 40 caracteres aleatorios repetidos 500
    # veces sí merecen una mirada.
    assert resultado["sospechoso"] is True


def test_txt_solo_no_alcanza():
    """Verificaciones de dominio y sistemas antispam usan TXT legítimamente."""
    resultado = evaluar_grupo(_grupo(
        padre="_dmarc.ejemplo.com", total=200, distintos=3,
        largo_promedio=6.0, entropia_promedio=2.5, tipos_de_datos=200,
    ))
    assert len(resultado["senales"]) == 1
    assert resultado["sospechoso"] is False


# ------------------------------------------- actividad anómala


def test_un_pico_real_se_marca():
    hallazgo = evaluar_actividad("192.168.1.20", 3000, [400, 380, 420, 390, 410, 400])
    assert hallazgo is not None
    assert hallazgo["factor"] > 3


def test_sin_historia_suficiente_no_se_inventa_una_base():
    """Con dos o tres horas de datos cualquier cosa parece un pico."""
    assert evaluar_actividad("192.168.1.20", 3000, [400, 380]) is None


def test_un_equipo_que_estaba_apagado_no_es_una_anomalia():
    """Pasar de 2 consultas por hora a 40 es veinte veces la base, pero 40
    consultas no son una anomalía. Sin el piso absoluto el panel se llena de
    equipos que recién se prenden."""
    assert evaluar_actividad("192.168.1.30", 40, [2, 1, 3, 2, 2, 1]) is None


def test_se_usa_la_mediana_y_no_el_promedio():
    """Con promedio, un pico previo arrastra la base hacia arriba y esconde el
    pico siguiente, que es justo lo que se quiere ver. Historia con un pico
    aislado de 5000: el promedio da ~900 y 2000 no lo superaría por 3; la
    mediana da 300 y sí."""
    historia = [300, 300, 5000, 280, 320, 300]
    hallazgo = evaluar_actividad("192.168.1.20", 2000, historia)
    assert hallazgo is not None
    assert hallazgo["base"] == pytest.approx(300.0)


def test_un_ritmo_estable_no_se_marca():
    assert evaluar_actividad("192.168.1.20", 420, [400, 380, 420, 390, 410, 400]) is None


# ---------------------------------------------- de punta a punta con la base


def _sembrar(db, cliente, nombres, qtype="A", cuando=None, veces=1):
    cuando = cuando or datetime.now(timezone.utc)
    import sqlite3
    from contextlib import closing as _closing

    from securedns.deteccion import dominio_padre as _padre

    with _closing(sqlite3.connect(db.db_path)) as conn:
        for nombre in nombres:
            for _ in range(veces):
                conn.execute(
                    "INSERT INTO queries (timestamp, client_ip, domain, qtype, blocked,"
                    " reason, source, duration_ms, noisy, category, parent)"
                    " VALUES (?,?,?,?,0,'','upstream_primary_dot',1.0,0,'',?)",
                    (cuando.isoformat(), cliente, nombre, qtype, _padre(nombre)),
                )
        conn.commit()


def test_encuentra_un_tunel_en_la_base(tmp_path):
    import hashlib

    db = LoggerDB(str(tmp_path / "l.db"))
    # 120 nombres distintos, largos y aleatorios, todos bajo el mismo padre.
    nombres = [
        hashlib.sha256(str(i).encode()).hexdigest()[:48] + ".tunel.atacante.com"
        for i in range(120)
    ]
    _sembrar(db, "192.168.1.20", nombres, qtype="TXT")
    # Y navegación normal de otro equipo, que no se tiene que marcar.
    _sembrar(db, "192.168.1.10", ["www.google.com", "mail.google.com"], veces=100)

    hallazgos = db.tunneling(24)

    assert len(hallazgos) == 1
    assert hallazgos[0]["padre"] == "atacante.com"
    assert hallazgos[0]["cliente"] == "192.168.1.20"
    assert len(hallazgos[0]["senales"]) >= 3


def test_no_marca_la_navegacion_normal(tmp_path):
    db = LoggerDB(str(tmp_path / "l.db"))
    _sembrar(db, "192.168.1.10",
             ["www.google.com", "mail.google.com", "drive.google.com"], veces=200)

    assert db.tunneling(24) == []


def test_el_filtro_de_ruido_no_esconde_una_deteccion(tmp_path):
    """Ocultar telemetría existe para que se vean las cosas raras. Sería
    absurdo que justamente tape un hallazgo."""
    import hashlib
    import sqlite3
    from contextlib import closing as _closing

    from securedns.deteccion import dominio_padre as _padre

    db = LoggerDB(str(tmp_path / "l.db"))
    ahora = datetime.now(timezone.utc).isoformat()
    with _closing(sqlite3.connect(db.db_path)) as conn:
        for i in range(120):
            nombre = hashlib.sha256(str(i).encode()).hexdigest()[:48] + ".t.malo.com"
            conn.execute(
                "INSERT INTO queries (timestamp, client_ip, domain, qtype, blocked,"
                " reason, source, duration_ms, noisy, category, parent)"
                " VALUES (?,?,?,'TXT',0,'','upstream_primary_dot',1.0,1,'',?)",
                (ahora, "192.168.1.20", nombre, _padre(nombre)),
            )
        conn.commit()

    # Marcadas como ruido, pero la detección las mira igual.
    assert db.tunneling(24) != []


def test_lo_viejo_no_entra_en_la_ventana(tmp_path):
    import hashlib

    db = LoggerDB(str(tmp_path / "l.db"))
    nombres = [
        hashlib.sha256(str(i).encode()).hexdigest()[:48] + ".tunel.viejo.com"
        for i in range(120)
    ]
    _sembrar(db, "192.168.1.20", nombres, qtype="TXT",
             cuando=datetime.now(timezone.utc) - timedelta(days=3))

    assert db.tunneling(24) == []


def test_el_padre_se_completa_en_una_base_vieja(tmp_path):
    """Una base de antes de que existiera la columna arrancaría ciega."""
    import sqlite3
    from contextlib import closing as _closing

    db = LoggerDB(str(tmp_path / "l.db"))
    with _closing(sqlite3.connect(db.db_path)) as conn:
        conn.execute(
            "INSERT INTO queries (timestamp, client_ip, domain, qtype, blocked,"
            " reason, source, duration_ms, noisy, category, parent)"
            " VALUES (?,?,?,'A',0,'','cache',1.0,0,'','')",
            (datetime.now(timezone.utc).isoformat(), "1.1.1.1", "a.b.ejemplo.com"),
        )
        conn.commit()

    assert db.recalcular_padres() == 1
    assert db.buscar(solo_bloqueadas=False)[0]["parent"] == "ejemplo.com"
    # Idempotente: correrlo de nuevo no toca nada.
    assert db.recalcular_padres() == 0


def test_el_padre_se_guarda_al_registrar(tmp_path):
    db = LoggerDB(str(tmp_path / "l.db"))
    db.log_query("1.1.1.1", "x.y.ejemplo.com.ar", "A", False, source="cache")
    assert db.buscar(solo_bloqueadas=False)[0]["parent"] == "ejemplo.com.ar"


# ------------------------------------------------------- el panel


@pytest.fixture()
def panel(tmp_path):
    (tmp_path / "bl.txt").write_text("", encoding="utf-8")
    (tmp_path / "al.txt").write_text("", encoding="utf-8")
    blocklist = Blocklist(str(tmp_path / "bl.txt"))
    allowlist = Allowlist(str(tmp_path / "al.txt"))
    db = LoggerDB(str(tmp_path / "l.db"))
    resolver = ThreatIntelResolver(
        blocklist=blocklist, logger_db=db,
        upstream_primary="127.0.0.1", upstream_fallback="127.0.0.1",
        allowlist=allowlist,
    )
    servidor = build_dashboard_server("127.0.0.1", 0, db, allowlist, blocklist, resolver)
    threading.Thread(target=servidor.serve_forever, daemon=True).start()
    time.sleep(0.2)
    try:
        yield servidor.server_address[1], db
    finally:
        servidor.shutdown()


def _pedir(puerto, ruta="/") -> str:
    con = socket.create_connection(("127.0.0.1", puerto), timeout=5)
    try:
        con.sendall(
            f"GET {ruta} HTTP/1.1\r\nHost: 127.0.0.1:{puerto}\r\n"
            "Connection: close\r\n\r\n".encode()
        )
        con.settimeout(5)
        datos = b""
        try:
            while len(datos) < 1_000_000:
                trozo = con.recv(8192)
                if not trozo:
                    break
                datos += trozo
        except socket.timeout:
            pass
        return datos.decode("utf-8", "replace")
    finally:
        con.close()


def test_el_panel_muestra_el_hallazgo_con_sus_motivos(panel):
    import hashlib

    puerto, db = panel
    nombres = [
        hashlib.sha256(str(i).encode()).hexdigest()[:48] + ".t.atacante.com"
        for i in range(120)
    ]
    _sembrar(db, "192.168.1.20", nombres, qtype="TXT")

    pagina = _pedir(puerto)

    assert "Posible tunneling por DNS" in pagina
    assert "atacante.com" in pagina
    assert "192.168.1.20" in pagina
    assert "nombres distintos" in pagina


def test_sin_hallazgos_el_panel_lo_dice_en_vez_de_quedar_vacio(panel):
    """Una pestaña vacía se lee como "esto no anda". Decir "nada que marcar"
    es información."""
    puerto, _db = panel
    pagina = _pedir(puerto)
    assert "Nada que marcar" in pagina


def test_el_panel_aclara_que_señala_y_no_bloquea(panel):
    puerto, _db = panel
    pagina = _pedir(puerto)
    assert "señalan, no bloquean" in pagina
