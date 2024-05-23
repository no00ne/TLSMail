import asyncio
import logging
import ssl

from aiosmtpd.controller import Controller

import AuthSMTP
import Config
import SimpleMessageHandler

# SMTP Configuration
host = Config.get_smtp_host()
port = 5880


async def run_smtp_server():
    # Create an SSL context
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(certfile='certificates/certificate.crt', keyfile='certificates/private.key')
    # Pass the SSL context to the SMTP server

    authenticator = AuthSMTP.Authenticator()
    handler = SimpleMessageHandler.RelayerHandler()
    controller = Controller(handler, hostname=host, port=port, authenticator=authenticator, auth_required=True,
                            tls_context=ssl_context,
                            auth_require_tls=True)  # 使用自定义的邮件处理器
    controller.start()


def run():
    logging.basicConfig(level=logging.DEBUG)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.create_task(run_smtp_server())  # type: ignore[unused-awaitable]
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        print("User abort indicated")
    finally:
        print("Cleaning up")
        loop.close()


if __name__ == '__main__':
    run()
