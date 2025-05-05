# -*- coding: utf-8 -*-
import os
import requests

from lxml import etree
from pytrustnfe.xml import render_xml, sanitize_response
from pytrustnfe.certificado import extract_cert_and_key_from_pfx, save_cert_key
from pytrustnfe.nfse.assinatura import Signer

URL = 'https://wsblumenau1.simplissweb.com.br/nfseservice.svc'


def _get_headers(method):
    return {'Content-Type': 'text/xml; charset=utf-8', 'SOAPAction': "http://nfse.abrasf.org.br/INfseService/" + method}


def _render_xml(method, **kwargs):
    path = os.path.join(os.path.dirname(__file__), 'templates')
    xml_send = render_xml(path, '%s.xml' % method, True, **kwargs)
    xml_send = etree.tostring(xml_send)
    return xml_send


def _send(certificate, method, retry=0, **kwargs):
    try:
        cert_content, key_content = extract_cert_and_key_from_pfx(certificate.pfx, certificate.password)
        cert_filename, key_filename = save_cert_key(cert_content, key_content)

        path = os.path.join(os.path.dirname(__file__), 'templates')
        body = render_xml(path, '%s.xml' % method, False, **kwargs).decode("utf-8")
        print(body)
        if method in ["GerarNfse", "RecepcionarLoteRps", "CancelarNfse"]:
            signer = Signer()
            if method == "RecepcionarLoteRps":
                # Assina cada RPS e adiciona no lote
                for rps in kwargs["nfse"]["lista_rps"]:
                    body_rps = render_xml(path, 'Rps.xml', False, **rps)
                    body_rps_signed = signer.sign_xml(body_rps, f'rps{rps["numero"]}', cert_content, key_content)
                    body = body.replace(f"rps_{rps['numero']}_rps", body_rps_signed)
                body = body.replace("\n", "")

            # Assina o lote
            body = signer.sign_xml(body.encode('utf-8'), 'L1', cert_content, key_content)

        data = f'<?xml version="1.0" encoding="UTF-8"?>' \
               '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" ' \
               'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ' \
               'xmlns:ns0="http://schemas.xmlsoap.org/soap/envelope/" ' \
               'xmlns:ns1="http://nfse.abrasf.org.br">' \
               '<SOAP-ENV:Header/>' \
               '<ns0:Body><ns1:' + method + 'Request>' \
                                            '<nfseCabecMsg><![CDATA[<cabecalho versao="2.03" ' \
                                            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ' \
                                            'xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns="http://www.abrasf.org.br/nfse.xsd">' \
                                            '<versaoDados>2.03</versaoDados></cabecalho>]]>' \
                                            '</nfseCabecMsg><nfseDadosMsg><![CDATA[' + body + ']]></nfseDadosMsg></ns1:' + method + 'Request></ns0:Body>' \
                                                                                                                                    '</SOAP-ENV:Envelope>'
        data = data.encode()
        print(data)
        session = requests.Session()
        session.cert = (cert_filename, key_filename)
        response = session.post(URL, data=data, headers=_get_headers(method), timeout=30)
        print(response.status_code)
        if response.status_code != 200 or "E900" in response.text:
            error = "Erro ao exportar a RPS. %d - %s" % (response.status_code, response.text)
            print(error)
            return {
                'sent_xml': data,
                'received_xml': error,
                'object': None
            }
        else:
            response, obj = sanitize_response(response.text)
            if method == "RecepcionarLoteRps":
                response, obj = sanitize_response(str(obj.Body.RecepcionarLoteRpsResponse['outputXML']))
            elif method == "ConsultarLoteRps":
                response, obj = sanitize_response(str(obj.Body.ConsultarLoteRpsResponse['outputXML']))
            elif method == "GerarNfse":
                response, obj = sanitize_response(str(obj.Body.GerarNfseResponse['outputXML']))
            elif method == "CancelarNfse":
                response, obj = sanitize_response(str(obj.Body.CancelarNfseResponse['outputXML']))
            elif method == "ConsultarNfseFaixa":
                response, obj = sanitize_response(str(obj.Body.ConsultarNfseFaixaResponse['outputXML']))
            return {
                'sent_xml': data,
                'received_xml': response,
                'object': obj
            }
    except Exception as e:
        print(e)
        raise e


def gerar_nfse(certificate, **kwargs):
    if "xml" not in kwargs:
        kwargs['xml'] = _render_xml('GerarNfse', **kwargs)
    return _send(certificate, 'GerarNfse', 0, **kwargs)


def recepcionar_lote_rps(certificado, **kwargs):
    if "xml" not in kwargs:
        kwargs['xml'] = _render_xml('RecepcionarLoteRps', **kwargs)
    return _send(certificado, 'RecepcionarLoteRps', 0, **kwargs)


def consultar_lote_rps(certificado, **kwargs):
    if "xml" not in kwargs:
        kwargs['xml'] = _render_xml('ConsultarLoteRps', **kwargs)
    return _send(certificado, 'ConsultarLoteRps', 2, **kwargs)


def cancelar_nfse(certificate, **kwargs):
    if "xml" not in kwargs:
        kwargs['xml'] = _render_xml('CancelarNfse', **kwargs)
    return _send(certificate, 'CancelarNfse', 0, **kwargs)


def consultar_nfse(certificate, **kwargs):
    if "xml" not in kwargs:
        kwargs['xml'] = _render_xml('ConsultarNfseFaixa', **kwargs)
    return _send(certificate, 'ConsultarNfseFaixa', 0, **kwargs)