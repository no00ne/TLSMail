import asyncio
import ssl
from typing import List


class Mail:
    def __init__(self, sender, recipient, date, subject, mime_version, content_type, content_transfer_encoding, body):
        self.sender = sender
        self.recipient = recipient
        self.date = date
        self.subject = subject
        self.mime_version = mime_version
        self.content_type = content_type
        self.content_transfer_encoding = content_transfer_encoding
        self.body = body


class MailRepository:
    def __init__(self):
        self.mails = []

    def findByRecipient(self, recipient):
        return [mail for mail in self.mails if mail.recipient == recipient]


class TLSIMAPServer:
    def __init__(self, host, port, username, password, mail_repository):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.mail_repository = mail_repository

    async def start_server(self):
        server = await asyncio.start_server(
            self.handle_client,
            self.host,
            self.port,
            ssl=ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        )

        async with server:
            await server.serve_forever()

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        while True:
            line = await reader.readline()
            if not line:
                break
            line = line.decode().strip()
            if line == "FETCH":
                recipient = await reader.readline()
                recipient = recipient.decode().strip()
                await self.fetch_and_send_mails(recipient, writer)

    def fetch_mails_from_database(self, recipient):
        return self.mail_repository.findByRecipient(recipient)

    async def fetch_and_send_mails(self, recipient, writer):
        mails = self.fetch_mails_from_database(recipient)
        for mail in mails:
            writer.write(f"FROM:{mail.sender}\n".encode())
            writer.write(f"TO:{mail.recipient}\n".encode())
            writer.write(f"DATE:{mail.date}\n".encode())
            writer.write(f"SUBJECT:{mail.subject}\n".encode())
            writer.write(f"MIME-VERSION: {mail.mime_version}\n".encode())
            writer.write(f"CONTENT-TYPE: {mail.content_type}\n".encode())
            writer.write(f"CONTENT-TRANSFER-ENCODING: {mail.content_transfer_encoding}\n".encode())
            writer.write(f"\n {mail.body}\n".encode())
        await writer.drain()


# Usage
mail_repository = MailRepository()
server = TLSIMAPServer('localhost', 993, 'username', 'password', mail_repository)
asyncio.run(server.start_server())
