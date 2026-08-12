"""Fase 1 del punto 3: publicarle a Pi-hole las listas de Secure-Intel.

Los tests de la API no hablan con un Pi-hole de verdad: se reemplaza
`requests` por uno falso que anota qué se le pidió. Eso permite verificar las
tres cosas que solo se ven mirando el pedido en crudo, y que son justo las
que se rompen en la vida real: dónde va el `type`, dónde va el `sid`, y qué
pasa cuando la sesión vence.
"""

import platform
import types

import pytest

from securedns import publicador
from securedns.config_loader import Config, PiholeConfig
from securedns.pihole_api import (ClientePihole, limpiar_ansi,
                                  resumen_de_gravity)


# --------------------------------------------------------------- Pi-hole falso

class RespuestaFalsa:
    def __init__(self, status_code=200, datos=None, texto=""):
        self.status_code = status_code
        self._datos = datos
        self.text = texto

    def json(self):
        if self._datos is None:
            raise ValueError("no es json")
        return self._datos


class RequestsFalso:
    """Guarda cada llamada y contesta lo que le digan.

    `respuestas` es una función (metodo, url, kwargs) -> RespuestaFalsa.
    """

    def __init__(self, respuestas):
        self.respuestas = respuestas
        self.llamadas = []

    def request(self, metodo, url, **kwargs):
        self.llamadas.append((metodo, url, kwargs))
        return self.respuestas(metodo, url, kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)

    def delete(self, url, **kwargs):
        return self.request("DELETE", url, **kwargs)


def cliente_con(monkeypatch, respuestas, password="secreta"):
    falso = RequestsFalso(respuestas)
    monkeypatch.setattr("securedns.pihole_api.requests", falso)
    cliente = ClientePihole("http://127.0.0.1", password)
    return cliente, falso


def sesion_ok(sid="SID-1", validity=300):
    return RespuestaFalsa(200, {"session": {"sid": sid, "validity": validity}})


# ------------------------------------------------------------------ sesión

def test_entrar_guarda_el_sid(monkeypatch):
    cliente, falso = cliente_con(monkeypatch, lambda m, u, k: sesion_ok())
    ok, detalle = cliente.entrar()
    assert ok, detalle
    assert cliente.sid == "SID-1"
    # La contraseña va en el cuerpo del POST, no en la URL.
    metodo, url, kwargs = falso.llamadas[0]
    assert (metodo, url) == ("POST", "http://127.0.0.1/api/auth")
    assert kwargs["json"] == {"password": "secreta"}
    assert "secreta" not in url


def test_sin_password_no_sale_ni_un_pedido(monkeypatch):
    cliente, falso = cliente_con(monkeypatch, lambda m, u, k: sesion_ok(), password="")
    ok, detalle = cliente.entrar()
    assert not ok
    assert "PIHOLE_PASSWORD" in detalle
    assert falso.llamadas == []


def test_password_rechazada_no_se_repite_en_el_mensaje(monkeypatch):
    cliente, _ = cliente_con(monkeypatch, lambda m, u, k: RespuestaFalsa(401, {}))
    ok, detalle = cliente.entrar()
    assert not ok
    # El detalle termina en el panel y en el log: no puede llevar la clave.
    assert "secreta" not in detalle


def test_pihole_sin_password_puesta_se_avisa(monkeypatch):
    """Contesta 200 pero sin sid. Antes eso daba un 401 confuso más adelante."""
    cliente, _ = cliente_con(
        monkeypatch, lambda m, u, k: RespuestaFalsa(200, {"session": {"valid": True}}))
    ok, detalle = cliente.entrar()
    assert not ok
    assert "contraseña" in detalle.lower()


def test_el_sid_viaja_en_la_cabecera_y_no_en_la_url(monkeypatch):
    def responder(metodo, url, kwargs):
        if url.endswith("/api/auth"):
            return sesion_ok()
        return RespuestaFalsa(200, {"lists": []})

    cliente, falso = cliente_con(monkeypatch, responder)
    cliente.listas()
    _, url, kwargs = falso.llamadas[-1]
    assert kwargs["headers"]["X-FTL-SID"] == "SID-1"
    assert "sid=" not in url


# ------------------------------------------------------------------ listas

def test_el_type_va_en_la_query_y_no_en_el_cuerpo(monkeypatch):
    """La trampa de esta API. Con `type` adentro del JSON, Pi-hole contesta
    "Invalid request: Specify type parameter" y la lista no se agrega nunca."""
    def responder(metodo, url, kwargs):
        if url.endswith("/api/auth"):
            return sesion_ok()
        return RespuestaFalsa(201, {})

    cliente, falso = cliente_con(monkeypatch, responder)
    ok, _ = cliente.agregar_lista("file:///tmp/lista.txt", "prueba")
    assert ok
    metodo, url, kwargs = falso.llamadas[-1]
    assert metodo == "POST"
    assert url == "http://127.0.0.1/api/lists?type=block"
    assert "type" not in kwargs["json"]
    assert kwargs["json"]["address"] == "file:///tmp/lista.txt"
    assert kwargs["json"]["enabled"] is True


def test_lista_repetida_no_es_un_error(monkeypatch):
    def responder(metodo, url, kwargs):
        if url.endswith("/api/auth"):
            return sesion_ok()
        return RespuestaFalsa(409, {"error": {"message": "already exists"}})

    cliente, _ = cliente_con(monkeypatch, responder)
    ok, detalle = cliente.agregar_lista("file:///tmp/lista.txt")
    assert ok
    assert "ya estaba" in detalle


def test_asegurar_lista_no_agrega_dos_veces(monkeypatch):
    def responder(metodo, url, kwargs):
        if url.endswith("/api/auth"):
            return sesion_ok()
        if metodo == "GET":
            return RespuestaFalsa(200, {"lists": [{"address": "file:///tmp/lista.txt"}]})
        raise AssertionError("no tendría que haber intentado agregarla")

    cliente, falso = cliente_con(monkeypatch, responder)
    ok, detalle = cliente.asegurar_lista("file:///tmp/lista.txt")
    assert ok
    assert "ya estaba" in detalle
    assert not any(m == "POST" and "lists" in u for m, u, _ in falso.llamadas)


# --------------------------------------------------------- sesión que vence

def test_ante_un_401_entra_de_nuevo_y_reintenta_una_vez(monkeypatch):
    """Sin esto la publicación anda el primer día y falla en silencio después."""
    estado = {"logins": 0, "gets": 0}

    def responder(metodo, url, kwargs):
        if url.endswith("/api/auth"):
            estado["logins"] += 1
            return sesion_ok(sid=f"SID-{estado['logins']}")
        estado["gets"] += 1
        if estado["gets"] == 1:
            return RespuestaFalsa(401, {})
        return RespuestaFalsa(200, {"lists": [{"address": "x"}]})

    cliente, _ = cliente_con(monkeypatch, responder)
    listas, error = cliente.listas()
    assert error == ""
    assert listas == [{"address": "x"}]
    assert estado["logins"] == 2  # entró, se venció, volvió a entrar
    assert cliente.sid == "SID-2"


def test_un_401_que_no_se_arregla_no_reintenta_para_siempre(monkeypatch):
    estado = {"gets": 0}

    def responder(metodo, url, kwargs):
        if url.endswith("/api/auth"):
            return sesion_ok()
        estado["gets"] += 1
        return RespuestaFalsa(401, {})

    cliente, _ = cliente_con(monkeypatch, responder)
    listas, error = cliente.listas()
    assert listas is None
    assert estado["gets"] == 2  # el original y UN reintento, no más


def test_pihole_apagado_no_lanza(monkeypatch):
    def responder(metodo, url, kwargs):
        raise ConnectionError("connection refused")

    cliente, _ = cliente_con(monkeypatch, responder)
    ok, detalle = cliente.entrar()
    assert not ok
    assert "no pude llegar" in detalle


def test_url_invalida_se_rechaza_antes_de_mandar_la_password(monkeypatch):
    falso = RequestsFalso(lambda m, u, k: sesion_ok())
    monkeypatch.setattr("securedns.pihole_api.requests", falso)
    cliente = ClientePihole("file:///etc/passwd", "secreta")
    ok, detalle = cliente.entrar()
    assert not ok
    assert falso.llamadas == []


# ----------------------------------------------------------------- gravity

def test_gravity_limpia_los_codigos_de_color():
    crudo = "\x1b[1m\x1b[32m[✓]\x1b[0m Building tree\x1b[K"
    assert limpiar_ansi(crudo) == "[✓] Building tree"


def test_resumen_de_gravity_se_queda_con_lo_que_dice_algo():
    salida = ("\x1b[K  [i] Progress 10%\n"
              "\x1b[K  [i] Progress 90%\n"
              "  [i] Number of gravity domains: 120000 (98000 unique domains)\n")
    resumen = resumen_de_gravity(salida)
    assert "120000" in resumen
    assert "Progress" not in resumen


def test_gravity_usa_el_endpoint_documentado(monkeypatch):
    def responder(metodo, url, kwargs):
        if url.endswith("/api/auth"):
            return sesion_ok()
        return RespuestaFalsa(200, None, texto="[i] Number of gravity domains: 5")

    cliente, falso = cliente_con(monkeypatch, responder)
    ok, detalle = cliente.gravity()
    assert ok
    assert "5" in detalle
    metodo, url, _ = falso.llamadas[-1]
    assert (metodo, url) == ("POST", "http://127.0.0.1/api/action/gravity")


# --------------------------------------------------------------- publicador

def config_de_prueba(tmp_path, **extra) -> Config:
    cfg = Config()
    cfg.pihole = PiholeConfig(habilitado=True,
                              carpeta_listas=str(tmp_path / "listas"),
                              nombre_lista="secureintel_dominios.txt",
                              **extra)
    return cfg


class ClienteFalso:
    def __init__(self, ok_lista=True):
        self.ok_lista = ok_lista
        self.listas_pedidas = []
        self.gravity_corrido = 0

    def asegurar_lista(self, address, comentario="", tipo="block"):
        self.listas_pedidas.append(address)
        return self.ok_lista, "ok" if self.ok_lista else "Pi-hole dijo que no"

    def gravity(self):
        self.gravity_corrido += 1
        return True, "gravity ok"


def con_dominios(monkeypatch, dominios):
    monkeypatch.setattr(publicador.intel_puente, "valores",
                        lambda tipo, cats, raiz=None: set(dominios))


def test_publicar_escribe_el_archivo_y_registra_la_lista(monkeypatch, tmp_path):
    con_dominios(monkeypatch, {"malo.com", "peor.net"})
    cfg = config_de_prueba(tmp_path)
    cliente = ClienteFalso()

    informe = publicador.publicar(cfg, cliente)

    assert informe["ok"], informe["detalle"]
    destino = tmp_path / "listas" / "secureintel_dominios.txt"
    contenido = destino.read_text(encoding="utf-8")
    assert "malo.com" in contenido and "peor.net" in contenido
    assert cliente.listas_pedidas == [f"file://{destino}"]
    assert cliente.gravity_corrido == 1


def test_el_archivo_es_una_lista_pelada_sin_marcas_de_categoria(monkeypatch, tmp_path):
    """gravity come un dominio por línea. Las marcas `# categoria:` son del
    formato del resolutor propio y acá no van."""
    con_dominios(monkeypatch, {"malo.com"})
    cfg = config_de_prueba(tmp_path)
    publicador.publicar(cfg, ClienteFalso())
    lineas = (tmp_path / "listas" / "secureintel_dominios.txt").read_text().splitlines()
    utiles = [l for l in lineas if l and not l.startswith("#")]
    assert utiles == ["malo.com"]


@pytest.mark.skipif(platform.system() == "Windows",
                    reason="los permisos POSIX no existen en Windows, y Pi-hole "
                           "tampoco corre ahí: el caso no aplica")
def test_el_archivo_queda_legible_para_el_usuario_pihole(monkeypatch, tmp_path):
    """gravity corre como el usuario `pihole` cuando lo dispara la API, no
    como root. Con los 0600 que deja mkstemp, no podría leerlo."""
    con_dominios(monkeypatch, {"malo.com"})
    cfg = config_de_prueba(tmp_path)
    publicador.publicar(cfg, ClienteFalso())
    destino = tmp_path / "listas" / "secureintel_dominios.txt"
    assert destino.stat().st_mode & 0o044 == 0o044


def test_nunca_publica_una_lista_vacia(monkeypatch, tmp_path):
    """Publicar cero dominios y correr gravity apaga el bloqueo de toda la
    casa sin un solo error en pantalla."""
    con_dominios(monkeypatch, set())
    cfg = config_de_prueba(tmp_path)
    cfg.filtering.feeds_blocklist_path = str(tmp_path / "no_existe.txt")
    cliente = ClienteFalso()

    informe = publicador.publicar(cfg, cliente)

    assert not informe["ok"]
    assert informe["escribio"] is False
    assert cliente.gravity_corrido == 0
    assert not (tmp_path / "listas" / "secureintel_dominios.txt").exists()


def test_no_publica_si_la_lista_encogio_a_la_mitad(monkeypatch, tmp_path):
    con_dominios(monkeypatch, {f"d{i}.com" for i in range(100)})
    cfg = config_de_prueba(tmp_path)
    publicador.publicar(cfg, ClienteFalso())

    con_dominios(monkeypatch, {"d1.com", "d2.com"})
    cliente = ClienteFalso()
    informe = publicador.publicar(cfg, cliente)

    assert not informe["ok"]
    assert "encogió" in informe["detalle"]
    assert cliente.gravity_corrido == 0
    # Y lo importante: la lista vieja sigue puesta.
    contenido = (tmp_path / "listas" / "secureintel_dominios.txt").read_text()
    assert "d50.com" in contenido


def test_forzar_pasa_por_encima_de_la_guarda_de_encogimiento(monkeypatch, tmp_path):
    con_dominios(monkeypatch, {f"d{i}.com" for i in range(100)})
    cfg = config_de_prueba(tmp_path)
    publicador.publicar(cfg, ClienteFalso())

    con_dominios(monkeypatch, {"d1.com"})
    informe = publicador.publicar(cfg, ClienteFalso(), forzar=True)
    assert informe["ok"]
    assert informe["total"] == 1


def test_no_corre_gravity_si_la_lista_no_cambio(monkeypatch, tmp_path):
    """Reconstruir el árbol cuesta minutos de CPU y no cambiaría nada."""
    con_dominios(monkeypatch, {"malo.com", "peor.net"})
    cfg = config_de_prueba(tmp_path)
    publicador.publicar(cfg, ClienteFalso())

    cliente = ClienteFalso()
    informe = publicador.publicar(cfg, cliente)

    assert informe["ok"]
    assert informe["escribio"] is False
    assert cliente.gravity_corrido == 0
    assert "no hizo falta" in informe["gravity"]


def test_si_cambio_un_dominio_si_corre_gravity(monkeypatch, tmp_path):
    con_dominios(monkeypatch, {"malo.com"})
    cfg = config_de_prueba(tmp_path)
    publicador.publicar(cfg, ClienteFalso())

    con_dominios(monkeypatch, {"malo.com", "nuevo.com"})
    cliente = ClienteFalso()
    publicador.publicar(cfg, cliente)
    assert cliente.gravity_corrido == 1


def test_correr_gravity_apagado_publica_pero_no_reconstruye(monkeypatch, tmp_path):
    con_dominios(monkeypatch, {"malo.com"})
    cfg = config_de_prueba(tmp_path, correr_gravity=False)
    cliente = ClienteFalso()
    informe = publicador.publicar(cfg, cliente)
    assert informe["ok"]
    assert cliente.gravity_corrido == 0
    assert "correr_gravity" in informe["detalle"]


def test_address_a_mano_para_el_caso_remoto(monkeypatch, tmp_path):
    """Cuando Pi-hole está en otra máquina, file:// no sirve: buscaría el
    archivo en SU disco."""
    con_dominios(monkeypatch, {"malo.com"})
    cfg = config_de_prueba(tmp_path, address="http://192.168.1.50:8080/lista.txt")
    cliente = ClienteFalso()
    publicador.publicar(cfg, cliente)
    assert cliente.listas_pedidas == ["http://192.168.1.50:8080/lista.txt"]


def test_si_pihole_no_toma_la_lista_no_corre_gravity(monkeypatch, tmp_path):
    con_dominios(monkeypatch, {"malo.com"})
    cfg = config_de_prueba(tmp_path)
    cliente = ClienteFalso(ok_lista=False)
    informe = publicador.publicar(cfg, cliente)
    assert not informe["ok"]
    assert cliente.gravity_corrido == 0


def test_apagado_no_hace_nada(monkeypatch, tmp_path):
    con_dominios(monkeypatch, {"malo.com"})
    cfg = config_de_prueba(tmp_path)
    cfg.pihole.habilitado = False
    cliente = ClienteFalso()
    informe = publicador.publicar(cfg, cliente)
    assert informe["ok"] and informe["salteado"]
    assert cliente.listas_pedidas == []


def test_cae_al_archivo_de_texto_si_intel_no_esta(monkeypatch, tmp_path):
    """Alguien que clonó solo SecureDNS igual puede publicar en su Pi-hole."""
    con_dominios(monkeypatch, set())
    archivo = tmp_path / "blocklist_feeds.txt"
    archivo.write_text("# categoria: malware\nmalo.com\npeor.net\n", encoding="utf-8")
    cfg = config_de_prueba(tmp_path)
    cfg.filtering.feeds_blocklist_path = str(archivo)

    dominios, origen = publicador.dominios_a_publicar(cfg)
    assert dominios == {"malo.com", "peor.net"}
    assert "blocklist_feeds.txt" in origen


def test_carpeta_sin_permiso_lo_dice_claro(monkeypatch, tmp_path):
    con_dominios(monkeypatch, {"malo.com"})
    cfg = config_de_prueba(tmp_path)

    def explotar(*_a, **_k):
        raise PermissionError("Permission denied")

    monkeypatch.setattr(publicador, "escribir_atomico", explotar)
    informe = publicador.publicar(cfg, ClienteFalso())
    assert not informe["ok"]
    assert "permiso" in informe["detalle"]


def test_la_password_no_esta_en_el_config_yaml():
    """Regla de toda la suite: los secretos viven en el .env."""
    from securedns.config_loader import PiholeConfig as PC

    assert not any("password" in c for c in PC.__dataclass_fields__)
