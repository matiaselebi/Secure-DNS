"""Fase 5: el puntaje y el histórico por día.

El puntaje es lo más fácil de hacer mal de todo el proyecto: un número grande
que tranquiliza sin motivo es peor que no tener número. Estos tests fijan las
tres reglas que lo hacen defendible: cada punto sale de un hallazgo concreto,
cada descuento es clickeable, y no se descuenta por cosas que el usuario no
controla.
"""

import socket
import sqlite3
import sys
import threading
import time
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from securedns.blocklist import Allowlist, Blocklist  # noqa: E402
from securedns.dashboard import build_dashboard_server  # noqa: E402
from securedns.dns_server import ThreatIntelResolver  # noqa: E402
from securedns.logger_db import LoggerDB  # noqa: E402
from securedns.puntaje import calcular  # noqa: E402


# ------------------------------------------------------------ puntaje


def _estado(**kw):
    base = {
        "modo_upstream": "dot",
        "respaldo_sin_cifrar": False,
        "tunneling": [],
        "actividad_anomala": [],
        "amenazas_24h": {},
        "horas_desde_feeds": 1.0,
        "informativo": {},
    }
    base.update(kw)
    return base


def test_sin_hallazgos_da_cien():
    """El estado por defecto tiene que ser 100 y entenderse solo. Si el número
    base fuera 82 habría que explicar por qué."""
    resultado = calcular(_estado())
    assert resultado["puntaje"] == 100
    assert resultado["descuentos"] == []
    assert resultado["nivel"] == "bien"


def test_cada_descuento_dice_por_que_y_lleva_a_verlo():
    """Un puntaje que no se puede auditar es un adorno."""
    resultado = calcular(_estado(tunneling=[
        {"padre": "exfil.net", "cliente": "192.168.1.20"},
    ]))

    assert len(resultado["descuentos"]) == 1
    descuento = resultado["descuentos"][0]
    assert "exfil.net" in descuento["texto"]
    assert "192.168.1.20" in descuento["texto"]
    assert "exfil.net" in descuento["enlace"]
    assert descuento["puntos"] == 20


def test_no_se_descuenta_por_dnssec():
    """Que buena parte de internet no firme sus dominios no es un problema de
    tu red. Restarte puntos por eso sería culparte de algo ajeno."""
    resultado = calcular(_estado(informativo={"dnssec": {"porcentaje": 3.0}}))

    assert resultado["puntaje"] == 100
    # Pero sí se muestra, para que quede claro que está mirado.
    assert resultado["informativo"]["dnssec"]["porcentaje"] == 3.0


def test_el_texto_plano_pesa_mucho():
    """Anula la razón de ser del proyecto."""
    resultado = calcular(_estado(modo_upstream="udp"))
    assert resultado["puntaje"] == 75
    assert "texto plano" in resultado["descuentos"][0]["texto"]


def test_el_respaldo_sin_cifrar_pesa_poco():
    """Es la opción razonable por defecto, pero es una puerta abierta y
    conviene que se vea."""
    resultado = calcular(_estado(respaldo_sin_cifrar=True))
    assert resultado["puntaje"] == 95


def test_no_se_descuenta_dos_veces_por_el_transporte():
    """En modo UDP el respaldo no aplica: ya está todo en texto plano."""
    resultado = calcular(_estado(modo_upstream="udp", respaldo_sin_cifrar=True))
    assert resultado["puntaje"] == 75


def test_diez_tuneles_no_dejan_el_puntaje_en_cero():
    """Sin techo por categoría, el puntaje se clava en cero y deja de
    distinguir "un problema" de "un desastre", que es lo que tiene que
    distinguir."""
    resultado = calcular(_estado(tunneling=[
        {"padre": f"malo{i}.net", "cliente": "192.168.1.20"} for i in range(10)
    ]))

    assert resultado["puntaje"] == 60  # el tope de tunneling es 40
    assert sum(d["puntos"] for d in resultado["descuentos"]) == 40


def test_el_puntaje_nunca_baja_de_cero():
    resultado = calcular(_estado(
        modo_upstream="udp",
        tunneling=[{"padre": f"m{i}.net", "cliente": "1.1.1.1"} for i in range(5)],
        actividad_anomala=[
            {"cliente": f"192.168.1.{i}", "factor": 9.0} for i in range(5)
        ],
        amenazas_24h={"malware": 30, "phishing": 12},
        horas_desde_feeds=200,
    ))
    assert resultado["puntaje"] == 0
    assert resultado["nivel"] == "mal"


def test_un_dominio_reciente_suma_al_descuento():
    resultado = calcular(_estado(tunneling=[
        {"padre": "recien.net", "cliente": "192.168.1.20",
         "edad_reciente": True, "edad_dias": 3},
    ]))

    textos = " ".join(d["texto"] for d in resultado["descuentos"])
    assert "3 días" in textos
    assert resultado["puntaje"] == 70  # 20 de tunneling + 10 de dominio nuevo


def test_las_listas_viejas_descuentan():
    """Filtrar con información de hace días es filtrar peor, aunque no haya
    pasado nada malo todavía."""
    assert calcular(_estado(horas_desde_feeds=48))["puntaje"] == 85
    # Un ciclo salteado no alcanza: el normal es de 6 horas.
    assert calcular(_estado(horas_desde_feeds=8))["puntaje"] == 100


def test_sin_dato_de_feeds_no_se_castiga():
    """Si el archivo todavía no existe (primer arranque), no se sabe, y no
    saber no es lo mismo que estar mal."""
    assert calcular(_estado(horas_desde_feeds=None))["puntaje"] == 100


def test_una_amenaza_pedida_descuenta_aunque_se_haya_bloqueado():
    """Bloquearla está bien; que se haya pedido significa que hay algo en la
    red intentándolo."""
    resultado = calcular(_estado(amenazas_24h={"malware": 5}))
    assert resultado["puntaje"] == 85
    assert "malware" in resultado["descuentos"][0]["enlace"]


def test_la_publicidad_bloqueada_no_descuenta():
    """Es ruido de fondo: descontar por eso haría que el puntaje midiera
    cuánta publicidad hay en internet y no cuán segura está tu red."""
    resultado = calcular(_estado(amenazas_24h={}))
    assert resultado["puntaje"] == 100


# --------------------------------------------------------- histórico


def _sembrar_dias(db, dias_atras: list[int], por_dia: int = 10):
    ahora = datetime.now(timezone.utc)
    with closing(sqlite3.connect(db.db_path)) as conn:
        for d in dias_atras:
            momento = ahora - timedelta(days=d)
            for i in range(por_dia):
                conn.execute(
                    "INSERT INTO queries (timestamp, client_ip, domain, qtype,"
                    " blocked, reason, source, duration_ms, noisy, category, parent)"
                    " VALUES (?, '1.1.1.1', 'a.com', 'A', ?, '', 'cache', 1.0, 0,"
                    " '', 'a.com')",
                    (momento.isoformat(), 1 if i == 0 else 0),
                )
        conn.commit()


def test_se_resumen_los_dias_cerrados(tmp_path):
    db = LoggerDB(str(tmp_path / "l.db"))
    _sembrar_dias(db, [1, 2, 3])

    assert db.consolidar_dias() == 3
    historico = db.historico(30)
    assert len(historico) == 3
    assert all(total == 10 and bloq == 1 for _f, total, bloq in historico)


def test_el_dia_en_curso_se_consolida_y_sigue_creciendo(tmp_path):
    """El día de hoy también se consolida, porque el recorte puede llevarse sus
    filas antes de que el día termine. Lo que se guarda se SUMA, así que lo que
    entre después se agrega en la próxima vuelta en vez de pisarlo."""
    db = LoggerDB(str(tmp_path / "l.db"))
    _sembrar_dias(db, [0])

    assert db.consolidar_dias() == 1
    assert db.historico(30)[0][1] == 10

    _sembrar_dias(db, [0], por_dia=5)
    # Sin volver a consolidar, lo nuevo ya se ve: el histórico suma lo
    # consolidado más lo que entró después del marcador.
    assert db.historico(30)[0][1] == 15
    db.consolidar_dias()
    assert db.historico(30)[0][1] == 15


def test_consolidar_dos_veces_no_duplica(tmp_path):
    db = LoggerDB(str(tmp_path / "l.db"))
    _sembrar_dias(db, [1])
    db.consolidar_dias()

    assert db.consolidar_dias() == 0
    assert db.historico(30)[0][1] == 10


def test_el_recorte_no_borra_lo_que_no_esta_consolidado(tmp_path):
    """Es la regla que hace correcto al histórico: el recorte solo puede tocar
    lo que ya está sumado al resumen. Antes borraba por id sin mirar eso, así
    que en una red activa las filas del día en curso se iban antes de que ese
    día se consolidara y esos números no se recuperaban nunca."""
    db = LoggerDB(str(tmp_path / "l.db"), max_rows=5)
    _sembrar_dias(db, [0], por_dia=50)

    # Sin consolidar todavía: el recorte no puede borrar nada.
    assert db.prune() >= 0
    assert db.historico(30)[0][1] == 50


def test_el_recorte_no_se_lleva_el_historico(tmp_path):
    """Este es el punto entero de la tabla de resúmenes: el historial se poda,
    los números del pasado sobreviven. Sin esto, mostrar "12 meses" sería
    mentir, porque diría cero para todo lo ya borrado."""
    db = LoggerDB(str(tmp_path / "l.db"), max_rows=5)
    _sembrar_dias(db, [1, 2], por_dia=20)

    db.prune()

    # El historial quedó recortado a 5 filas...
    assert len(db.buscar(solo_bloqueadas=False, limit=100)) == 5
    # ...pero los dos días siguen enteros en el histórico.
    historico = db.historico(30)
    assert len(historico) == 2
    assert all(total == 20 for _f, total, _b in historico)


def test_los_dias_apagados_no_aparecen_como_cero(tmp_path):
    """Rellenar con ceros haría parecer que el DNS dejó de funcionar."""
    db = LoggerDB(str(tmp_path / "l.db"))
    _sembrar_dias(db, [1, 5])
    db.consolidar_dias()

    assert len(db.historico(30)) == 2


def test_la_ventana_recorta(tmp_path):
    db = LoggerDB(str(tmp_path / "l.db"))
    _sembrar_dias(db, [1, 20])
    db.consolidar_dias()

    assert len(db.historico(7)) == 1
    assert len(db.historico(30)) == 2


# ------------------------------------------------------------ panel


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


def test_el_resumen_es_la_primera_pestania(panel):
    puerto, _db = panel
    pagina = _pedir(puerto)
    assert 'data-tab="resumen"' in pagina
    assert "Seguridad del DNS de tu red" in pagina


def test_el_panel_aclara_que_el_puntaje_es_del_dns_y_no_de_la_red(panel):
    """Un 100 acá no dice nada del tráfico que no pasa por DNS. El puntaje de
    la red entera es de SecureCenter, que ve las tres capas."""
    puerto, _db = panel
    pagina = _pedir(puerto)
    assert "es el puntaje del DNS, no de la" in pagina


def test_el_puntaje_baja_con_un_hallazgo_real(panel):
    import hashlib

    puerto, db = panel
    ahora = datetime.now(timezone.utc).isoformat()
    with closing(sqlite3.connect(db.db_path)) as conn:
        for i in range(120):
            nombre = hashlib.sha256(str(i).encode()).hexdigest()[:50] + ".t.exfil.net"
            conn.execute(
                "INSERT INTO queries (timestamp, client_ip, domain, qtype, blocked,"
                " reason, source, duration_ms, noisy, category, parent)"
                " VALUES (?, '192.168.1.20', ?, 'TXT', 0, '', 'upstream_primary_dot',"
                " 1.0, 0, '', 'exfil.net')",
                (ahora, nombre),
            )
        conn.commit()

    pagina = _pedir(puerto)

    assert "exfil.net" in pagina
    assert "puntaje-numero" in pagina
    # No puede seguir en 100 con un túnel abierto.
    assert ">100<" not in pagina.split("puntaje-numero'>")[1][:10]


def test_el_historico_tiene_las_tres_ventanas(panel):
    puerto, _db = panel
    pagina = _pedir(puerto)
    assert "7 días" in pagina
    assert "30 días" in pagina
    assert "12 meses" in pagina


def test_una_ventana_inventada_cae_en_el_default(panel):
    puerto, _db = panel
    pagina = _pedir(puerto, "/?dias=99999")
    assert "Histórico por día" in pagina
