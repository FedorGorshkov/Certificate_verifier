# required libraries
import OpenSSL
from fastapi import FastAPI, UploadFile
from fastapi.responses import JSONResponse
import certifi
import requests

# Built-in libraries
import traceback

trusted_certs_store = OpenSSL.crypto.X509Store()
filled = False
app = FastAPI()


@app.post("/verify_certificate")
async def verify_certificate(crt: UploadFile, crt_encoding="PEM"):
    load_trusted_certs()
    if not filled:
        return JSONResponse(content={"Status": "error", "Message": "Couldnt get trusted root certs"}, status_code=500)
    if crt_encoding not in ["PEM", "ANS1", "DER"]:
        return JSONResponse(content={"Status": "error", "Message": f"crt_encoding should be PEM, ANS1 (or DER), "
                                                                   f"not {crt_encoding}"}, status_code=400)
    try:
        crt_to_verify = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM if crt_encoding == "PEM"
                                                        else OpenSSL.crypto.FILETYPE_ASN1, crt.file.read())
        if get_intermediate_cert(crt_to_verify) or try_to_verify(crt_to_verify):
            if try_to_verify(crt_to_verify):
                return JSONResponse(content={"Status": "success", "Correct": True,
                                             "Message": "Given certificate is correct and can be trusted"},
                                    status_code=200)
        else:
            return JSONResponse(content={"Status": "success", "Correct": False,
                                         "Message": "Given certificate is incorrect and can't be trusted"},
                                status_code=200)
    except Exception as e:
        return JSONResponse(content={"Status": "error", "Message": f"During execution of your request following error "
                                                                   f"occured: {str(e)}"}, status_code=400)


def load_trusted_certs() -> None:
    global trusted_certs_store, filled
    try:
        trusted_certs = certifi.contents().split("-----BEGIN CERTIFICATE-----")
        # Удаляем комментарии перед первым сертификатом
        del trusted_certs[0]
        for index in range(len(trusted_certs)):
            # Возвращаем начало сертификата
            trusted_certs[index] = "-----BEGIN CERTIFICATE-----" + trusted_certs[index]
            # Переводим запись в тип bytes (изначально certifi загружает их в виде str)
            trusted_certs[index] = bytes(trusted_certs[index], 'latin-1')
            trusted_certs_store.add_cert(OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,
                                                                         trusted_certs[index]))
        filled = True
    except Exception as e:
        print("Loading trusted certs failed, here's exception traceback:")
        traceback.print_exception(e)


def get_intermediate_cert(cert: OpenSSL.crypto.X509) -> bool:
    for index in range(cert.get_extension_count()):
        if cert.get_extension(index).get_short_name() == b'authorityInfoAccess':
            data = cert.get_extension(index).get_data()
            found = data.find(b".crt") + 4
            if found:
                text = data[:found][::-1]
                new_found = text.find(b"ptth")
                if new_found:
                    address = text[:new_found + 4][::-1]
                    try:
                        response = requests.get(address)
                        if response.ok:
                            intermediate_cert = OpenSSL.crypto.load_certificate(
                                OpenSSL.crypto.FILETYPE_ASN1, response.content)
                            if try_to_verify(intermediate_cert):
                                trusted_certs_store.add_cert(intermediate_cert)
                                return True
                    except Exception as e:
                        traceback.print_exception(e)
            break
    return False


def try_to_verify(some_crt: OpenSSL.crypto.X509) -> bool:
    store_ctx = OpenSSL.crypto.X509StoreContext(trusted_certs_store, some_crt)
    try:
        store_ctx.verify_certificate()
        return True
    except Exception:
        return False
