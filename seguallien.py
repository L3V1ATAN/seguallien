#!/usr/bin/env python
# -*- coding: utf-8 -*-
#Banner http://www.patorjk.com/software/taag/#p=display&h=1&v=0&f=Standard&t=SeguAllien
#Paso 1 sudo apt-get install python-pip nmap
#Paso 2 sudo pip install python-nmap
#https://www.youtube.com/watch?v=zZZVCULfDXs&t=395s
#https://subscription.packtpub.com/book/cloud-and-networking/9781788992510/14/ch14lvl1sec27/chapter-4-http-programming
#https://pypi.org/project/python-nmap/
#https://www.pythonparatodo.com/?p=251  
import sys
#import time
import nmap
import os

class SeguAllien:
    def jmap(lip):
        nm = nmap.PortScanner()
        print('Ejecucion jmap...')
        results = nm.scan(arguments='-sS -sV -n -Pn --top-ports 1000 -iL '+lip)
        port_open=''
        open_port=[]
        #results = nm.scan(arguments='-n -Pn -p 21 --script=/usr/share/nmap/scripts/ftp-anon.nse  -iL '+lip)
        #Script de vulnerabilidades
        #results=nm.scan(arguments='-p 21,23,80,3389 --script=/usr/share/nmap/scripts/vulners.nse -iL'+lip)
        #os.system('clear')
        #print (nm.command_line())
        #print (nm.scaninfo())
        #for host in nm.all_hosts():
        for host in nm.all_hosts():
            print('----------------------------------------------------')
            print('Host : %s (%s)' % (host, nm[host].hostname()))
            print('State : {0}'.format(nm[host].state())) 
            for proto in nm[host].all_protocols():
                print('++++++++++++++++++++++++++++++++++++')
                print('Protocol : %s' % proto)
                lport = nm[host][proto].keys()
                sorted(lport)
                for port in lport:
                    print ('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))
                    port_open=port_open+' '+str(port)
                   # print('Port OPEN: '+port_open+' '+str(host))
        #Convierte los puesrtos de string a lista
        open_port=str.split(port_open)          
        deldupli(open_port)

      
         
def deldupli(open_puerto):
    #Eliminar Duplicados
    open_puerto[:] = list(dict.fromkeys(open_puerto))
    #Ordenar Lista
    #open_puerto.sort()
    print('%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%')
    print('Puertos Abiertos :')    
    #Imprimir
    for i in range(0, len(open_puerto)):
        print(open_puerto[i],end=",")
        
def usage():
    print ("""Uso: seguallien.py {OPTION} {CADENA | HOST}
     OPCIONES:
      --help: Comandos de ayuda
      -iL, : Lista de IPs de archivo
     EJEMPLOS
      python seguallien.py -iL archivo""")

def banner():
    print ("""
  ____                          _     _  _  _              
 / ___|   ___   __ _  _   _    / \   | || |(_)  ___  _ __  
 \___ \  / _ \ / _` || | | |  / _ \  | || || | / _ \| '_ \ 
  ___) ||  __/| (_| || |_| | / ___ \ | || || ||  __/| | | |
 |____/  \___| \__, | \__,_|/_/   \_\|_||_||_| \___||_| |_|
               |___/                                       
                                                 BY:JEHEMO
    1. All Port Open TCP nmap
    2. ALL port Open UDP nmap
    3  Other options one
    4. Other options two  """ )
    

def main():  
    banner()
    opc = input('    Ingrese opcion : ')
    match opc:
        case '1':
            print ('Entro opcon 1')
            ip = input('    Ingrese nombre archivo con listado de IPs : ')
            #os.system('clear')
            banner()
            SeguAllien.jmap(ip)
        case '2':
            print ('Entro opcon 2')  
        case '3':
            print ('Entro opcon 3')  
        case '4':
            print ('Entro opcon 4')              
        case _:
            print ('opcion no valida')  
    
#    if (len(sys.argv) < 3 or sys.argv[1] == '--help' ):        
#        usage()
        #sys.exit(2)      
#    else:
#        banner()
#        if (sys.argv[1] == '-iL'):
        #print ("Paso el valor capturado de la IP")          
#          host=sys.argv[2]
          #EL valor captura es diferente de cero          
#          if len(host) != 0:            
#            SeguAllien.jmap(host)
          #No ingreso nada en el parametro
#          else:
#            usage()  

if __name__ == '__main__':
    main()

