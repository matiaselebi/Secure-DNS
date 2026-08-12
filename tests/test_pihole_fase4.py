"""Fase 4: la jubilación del resolutor propio.

Lo que se prueba acá no es que el resolutor se apague, sino las dos cosas que
hacen que apagarlo sea seguro: que nadie apunte el DNS del sistema a un
resolutor que no está escuchando, y que el panel no siga describiendo cosas
que dejaron de funcionar.
"""

from pathlib import Path

import pytest

from securedns import modo, net_config
from securedns.config_loader import Config, PiholeConfig

RAIZ = Path(__file__).resolve().parent.parent


def cfg_con(modo_dns: str, pihole_habilitado: bool) -> Config:
    cfg = Config()
    cfg.dns.modo = modo_dns
    cfg.pihole = PiholeConfig(habilitado=pihole_habilitado)
    return cfg


# --------------------------------------------------------------- qué modo

def test_auto_usa_pihole_si_esta_habilitado():
    assert modo.resolutor_activo(cfg_con("auto", True)) == modo.PIHOLE


def test_auto_usa_el_propio_si_pihole_no_esta():
    """El que clonó esto para usarlo de resolutor no tiene que tocar nada."""
    assert modo.resolutor_activo(cfg_con("auto", False)) == modo.PROPIO


def test_se_puede_forzar_el_propio_aunque_pihole_este_habilitado():
    """Sirve para volver atrás sin desconfigurar Pi-hole."""
    assert modo.resolutor_activo(cfg_con("propio", True)) == modo.PROPIO


def test_pedir_pihole_sin_tenerlo_habilitado_no_deja_a_nadie_resolviendo():
    """La contradicción peligrosa: si se obedeciera al pie de la letra, no
    resolvería nadie. Se avisa y se vuelve al único que puede funcionar solo."""
    avisos = []
    activo = modo.resolutor_activo(cfg_con("pihole", False), avisar=avisos.append)
    assert activo == modo.PROPIO
    assert any("pihole.habilitado" in a for a in avisos)


def test_un_modo_escrito_mal_no_rompe_nada():
    avisos = []
    activo = modo.resolutor_activo(cfg_con("piholeee", True), avisar=avisos.append)
    assert activo == modo.PIHOLE          # cae a auto, y auto ve Pi-hole listo
    assert any("desconocido" in a for a in avisos)


# ------------------------------------------------- el DNS del sistema

def test_en_modo_pihole_no_se_toca_el_dns_del_sistema():
    """El peor bug posible de esta migración: apuntar la máquina a un
    127.0.0.1 donde no escucha nadie es quedarse sin internet en silencio."""
    assert modo.toca_el_dns_del_sistema(cfg_con("pihole", True)) is False
    assert modo.toca_el_dns_del_sistema(cfg_con("propio", True)) is True


def test_tomar_el_dns_se_saltea_en_modo_pihole(monkeypatch):
    monkeypatch.setattr(net_config, "_modo_dice_que_toquemos_el_dns", lambda: False)

    def no_deberia(*_a, **_k):
        raise AssertionError("no tenía que tocar el adaptador")

    monkeypatch.setattr(net_config, "poner_nuestro_dns", no_deberia)
    resultado = net_config.tomar_el_dns_si_corresponde()
    assert resultado["salteado"] is True


def test_devolver_el_dns_se_saltea_en_modo_pihole(monkeypatch):
    monkeypatch.setattr(net_config, "_modo_dice_que_toquemos_el_dns", lambda: False)

    def no_deberia(*_a, **_k):
        raise AssertionError("no tenía que restaurar nada")

    monkeypatch.setattr(net_config, "restaurar_e_informar", no_deberia)
    assert net_config.devolver_el_dns_si_corresponde()["salteado"] is True


def test_en_modo_propio_se_toca_igual_que_siempre(monkeypatch):
    monkeypatch.setattr(net_config, "_modo_dice_que_toquemos_el_dns", lambda: True)
    llamadas = []
    monkeypatch.setattr(net_config, "poner_nuestro_dns",
                        lambda respaldo="9.9.9.9": llamadas.append(respaldo) or {"ok": 1})
    net_config.tomar_el_dns_si_corresponde()
    assert llamadas == ["9.9.9.9"]


def test_si_no_se_puede_leer_el_modo_se_asume_el_propio(monkeypatch):
    """Equivocarse para este lado es recuperable; para el otro deja la máquina
    sin resolver nombres."""
    import securedns.config_loader as cl

    def explotar(*_a, **_k):
        raise RuntimeError("config roto")

    monkeypatch.setattr(cl, "load_config", explotar)
    assert net_config._modo_dice_que_toquemos_el_dns() is True


# --------------------------------------------------------- honestidad

def test_el_resolutor_jubilado_no_inventa_un_cache():
    """Un panel que dice 'caché: 1.240' cuando no hay caché es la clase de
    mentira que la regla 10 prohíbe."""
    jubilado = modo.ResolutorJubilado()
    assert jubilado.cache_size() == 0
    assert jubilado.clear_cache() is None
    assert jubilado.jubilado is True


def test_la_descripcion_dice_que_no_aplica_en_modo_pihole():
    info = modo.descripcion(cfg_con("pihole", True))
    assert info["quien_resuelve"] == "Pi-hole"
    junto = " ".join(info["no_aplica"]).lower()
    assert "caché" in junto or "cache" in junto
    assert "tls" in junto
    assert "dns del sistema" in junto


def test_en_modo_propio_no_hay_nada_que_aclarar():
    info = modo.descripcion(cfg_con("propio", False))
    assert info["quien_resuelve"] == "SecureDNS"
    assert info["no_aplica"] == []


# ------------------------------------------------- el punto de entrada

def _fuente(nombre: str) -> str:
    return (RAIZ / nombre).read_text(encoding="utf-8")


def test_run_dns_no_levanta_el_servidor_en_modo_pihole():
    fuente = _fuente("scripts/run_dns.py")
    assert "None if resuelve_pihole" in fuente
    assert "if dns_server is not None:" in fuente


def test_run_dns_levanta_la_publicacion_y_la_importacion():
    fuente = _fuente("scripts/run_dns.py")
    assert "_publicar_periodicamente" in fuente
    assert "_importar_periodicamente" in fuente


def test_el_modo_se_decide_en_un_solo_lugar():
    """El bug que esto evita es el de siempre: la misma decisión escrita en
    varios lados y uno que se olvida de actualizar. Nadie fuera de modo.py
    tiene permitido comparar contra la clave cruda."""
    sospechosos = []
    for archivo in (RAIZ / "src" / "securedns").glob("*.py"):
        if archivo.name == "modo.py":
            continue
        texto = archivo.read_text(encoding="utf-8")
        for linea in texto.splitlines():
            if "cfg.dns.modo" in linea and "=" not in linea.split("cfg.dns.modo")[0]:
                sospechosos.append(f"{archivo.name}: {linea.strip()}")
    assert not sospechosos, "el modo se decide en modo.py y nada más: " + "; ".join(sospechosos)
