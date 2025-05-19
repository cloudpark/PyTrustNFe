# -*- coding: utf-8 -*-
import os

from pytrustnfe.nfse.assinatura import Signer
from lxml import etree
from pytrustnfe.certificado import extract_cert_and_key_from_pfx, save_cert_key
from pytrustnfe.client import get_authenticated_client
from pytrustnfe.xml import render_xml, sanitize_response


def _render_xml(method, **kwargs):
    path = os.path.join(os.path.dirname(__file__), 'templates')
    xml_send = render_xml(path, '%s.xml' % method, True, **kwargs)
    xml_send = etree.tostring(xml_send)

    return xml_send


def _validate(method, xml):
    path = os.path.join(os.path.dirname(__file__), 'templates')
    schema = os.path.join(path, '%s.xsd' % method)

    nfe = etree.fromstring(xml)
    esquema = etree.XMLSchema(etree.parse(schema))
    esquema.validate(nfe)
    erros = [x.message for x in esquema.error_log]
    return erros


def _send(certificado, method, **kwargs):
    path = os.path.join(os.path.dirname(__file__), 'templates')

    city_desc = kwargs['city_desc']
    url = f'https://{city_desc}.webiss.com.br/ws/nfse.asmx?wsdl'

    xml_send = render_xml(path, '%s.xml' % method, False, **kwargs)
    body = xml_send.decode("utf-8")
    cert_content, key_content = extract_cert_and_key_from_pfx(certificado.pfx, certificado.password)
    cert, key = save_cert_key(cert_content, key_content)

    signer = Signer()

    """    
    if method == "RecepcionarLoteRps":
        # TODO implementar para enviar o lote. Deve assinar cada RPS separadamente e depois assinar o lote
        for rps in kwargs["nfse"]["lista_rps"]:
            body_rps = render_xml(path, 'Rps.xml', False, **rps)
            body_rps = signer.sign_xml_webiss(body_rps, f'{rps["numero"]}', cert_content, key_content, 0)
            body = body.replace(f"rps_rps", body_rps)

        body = signer.sign_xml_webiss(body.encode('utf-8'), "R1", cert_content, key_content, 0)
    """

    # Assina o RPS
    body = signer.sign_xml_webiss(body.encode('utf-8'), "R1", cert_content, key_content, 0)

    client = get_authenticated_client(url, cert, key)
    client.set_options(location=f"https://{city_desc}.webiss.com.br/ws/nfse.asmx")
    cabec = '<cabecalho versao="2.02" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns="http://www.abrasf.org.br/nfse.xsd"><versaoDados>2.02</versaoDados></cabecalho>'

    response = getattr(client.service, method)(cabec, body).encode('utf-8')
    response, obj = sanitize_response(response)
    return {
        "sent_xml": xml_send,
        "received_xml": response,
        "object": obj
    }


def xml_recepcionar_lote_rps(**kwargs):
    return _render_xml('RecepcionarLoteRps', **kwargs)


def recepcionar_lote_rps(certificado, **kwargs):
    if "xml" not in kwargs:
        kwargs['xml'] = xml_recepcionar_lote_rps(**kwargs)
    return _send(certificado, 'RecepcionarLoteRps', **kwargs)


def xml_consultar_situacao_lote(**kwargs):
    return _render_xml('ConsultarSituacaoLoteRps', **kwargs)


def consultar_situacao_lote(certificado, **kwargs):
    if "xml" not in kwargs:
        kwargs['xml'] = xml_consultar_situacao_lote(**kwargs)
    return _send(certificado, 'ConsultarSituacaoLoteRps', **kwargs)


def xml_consultar_lote_rps(**kwargs):
    return _render_xml('ConsultarLoteRps', **kwargs)


def consultar_lote_rps(certificado, **kwargs):
    if "xml" not in kwargs:
        kwargs['xml'] = xml_consultar_lote_rps(**kwargs)
    return _send(certificado, 'ConsultarLoteRps', **kwargs)


def xml_cancelar_nfse(**kwargs):
    return _render_xml('CancelarNfse', **kwargs)


def cancelar_nfse(certificado, **kwargs):
    if "xml" not in kwargs:
        kwargs['xml'] = xml_cancelar_nfse(**kwargs)
    return _send(certificado, 'CancelarNfse', **kwargs)


def gerar_nfse(certificate, **kwargs):
    if "xml" not in kwargs:
        kwargs['xml'] = _render_xml('GerarNfse', **kwargs)
    return _send(certificate, 'GerarNfse', **kwargs)