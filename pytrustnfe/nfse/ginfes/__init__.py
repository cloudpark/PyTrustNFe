import os
import suds
from pytrustnfe.xml import render_xml, sanitize_response
from pytrustnfe.client import get_authenticated_client
from pytrustnfe.certificado import extract_cert_and_key_from_pfx, save_cert_key
from pytrustnfe.nfse.assinatura import Signer


def _render(certificado, method, **kwargs):
    path = os.path.join(os.path.dirname(__file__), 'templates')
    return render_xml(path, '%s.xml' % method, True, **kwargs)


def _send(certificado, method, **kwargs):
    path = os.path.join(os.path.dirname(__file__), 'templates')
    base_url = ''
    if kwargs['ambiente'] == 'producao':
        base_url = 'https://producao.ginfes.com.br/ServiceGinfesImpl?wsdl'
    else:
        base_url = 'https://homologacao.ginfes.com.br/ServiceGinfesImpl?wsdl'

    xml_send = render_xml(path, '%s.xml' % method, False, **kwargs)
    body = xml_send.decode("utf-8")

    cert_content, key_content = extract_cert_and_key_from_pfx(certificado.pfx, certificado.password)
    cert, key = save_cert_key(cert_content, key_content)

    signer = Signer()
    if method == "RecepcionarLoteRpsV3":
        for rps in kwargs["nfse"]["lista_rps"]:
            body_rps = render_xml(path, 'Rps.xml', False, **rps)
            body = body.replace(f"rps_{rps['numero']}_rps", body_rps.decode('utf-8'))

        body = signer.sign_xml_ginfes(body.encode('utf-8'), "L1", cert_content, key_content, 0)
    else:
        body = signer.sign_xml_ginfes(body.encode('utf-8'), None, cert_content, key_content, 0)

    client = get_authenticated_client(base_url, cert, key)
    client.set_options(location="https://producao.ginfes.com.br/ServiceGinfesImpl")
    try:
        header = '<ns2:cabecalho xmlns:ns2="http://www.ginfes.com.br/cabecalho_v03.xsd" versao="3"><versaoDados>3</versaoDados></ns2:cabecalho>' #noqa
        response = getattr(client.service, method)(header, body).encode('utf-8')
    except suds.WebFault as e:
        return {
            'sent_xml': body,
            'received_xml': e.fault.faultstring,
            'object': None
        }

    response, obj = sanitize_response(response)
    return {
        'sent_xml': xml_send,
        'received_xml': response,
        'object': obj
    }


def xml_recepcionar_lote_rps(certificado, **kwargs):
    return _render(certificado, 'RecepcionarLoteRpsV3', **kwargs)


def recepcionar_lote_rps(certificado, **kwargs):
    if "xml" not in kwargs:
        kwargs['xml'] = xml_recepcionar_lote_rps(certificado, **kwargs)
    return _send(certificado, 'RecepcionarLoteRpsV3', **kwargs)


def xml_consultar_situacao_lote(certificado, **kwargs):
    return _render(certificado, 'ConsultarSituacaoLoteRpsV3', **kwargs)


def consultar_situacao_lote(certificado, **kwargs):
    if "xml" not in kwargs:
        kwargs['xml'] = xml_consultar_situacao_lote(certificado, **kwargs)
    return _send(certificado, 'ConsultarSituacaoLoteRpsV3', **kwargs)


def consultar_nfse_por_rps(certificado, **kwargs):
    return _send(certificado, 'ConsultarNfsePorRpsV3', **kwargs)


def xml_consultar_lote_rps(certificado, **kwargs):
    return _render(certificado, 'ConsultarLoteRpsV3', **kwargs)


def consultar_lote_rps(certificado, **kwargs):
    if "xml" not in kwargs:
        kwargs['xml'] = xml_consultar_lote_rps(certificado, **kwargs)
    return _send(certificado, 'ConsultarLoteRpsV3', **kwargs)


def consultar_nfse(certificado, **kwargs):
    return _send(certificado, 'ConsultarNfseV3', **kwargs)


def xml_cancelar_nfse(certificado, **kwargs):
    return _render(certificado, 'CancelarNfseV3', **kwargs)


def cancelar_nfse(certificado, **kwargs):
    if "xml" not in kwargs:
        kwargs['xml'] = xml_cancelar_nfse(certificado, **kwargs)
    return _send(certificado, 'CancelarNfseV3', **kwargs)
