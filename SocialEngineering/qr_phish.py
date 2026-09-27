# language: Python 3, file: qr_phish.py, target: Windows/Linux
# Generates a QR code image pointing to attacker URL.
# pip install qrcode[pil]
import qrcode
import os

def main():
    url = input('Phishing URL (ex: http://evil.com/login): ').strip()
    outfile = input('Output image file (ex: qr.png): ').strip() or 'qr.png'
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10,
        border=4,
    )
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color='black', back_color='white')
    img.save(outfile)
    print(f'[+] QR code saved to {outfile}')
    print(f'[*] Points to: {url}')
    print('[*] Print or embed in email/document for delivery.')

if __name__ == '__main__':
    main()
