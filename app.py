from flask import Flask, render_template
import nmap

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan')
def scan_network():
    # สแกนเครือข่ายในช่วง IP (เปลี่ยนให้ตรงกับช่วง IP ที่เชื่อมต่อกับเราเตอร์)
    nm = nmap.PortScanner()
    
    # สมมุติว่าเราเตอร์มี IP 192.168.1.1 และช่วง IP ที่เราเตอร์กำหนดเป็น 192.168.1.0/24
    nm.scan(hosts='192.168.1.0/24', arguments='-sn')  # สแกนการเชื่อมต่อทุก IP ในช่วงนี้

    hosts = nm.all_hosts()
    devices = []

    for host in hosts:
        device_info = {
            'ip': host,
            'hostname': nm[host].hostname(),
            'state': nm[host].state()
        }
        devices.append(device_info)

    return render_template('testresult.html', devices=devices)

if __name__ == '__main__':
    app.run(debug=True)
