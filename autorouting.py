#!/usr/bin/env python3
 
# Import Standard
import datetime

from scapy.all import *

from conf import *


def sendMail(TO,
             FROMADDR,
             SUBJECT = 'Email Test',
             TEXT = 'Ignore thie email'):

    sendmail_location = "/usr/sbin/sendmail" # sendmail location
    p = os.popen("%s -t" % sendmail_location, "w")
    p.write("Return-Path: <sysadmin@schema31.it>")
    p.write("From: %s\n" % FROMADDR)
    p.write("To: %s\n" % TO)
    p.write("Subject: %s\n" % SUBJECT)
    p.write("\n") # blank line separating headers from body
    p.write(TEXT)
    status = p.close()
    if (status == 0 or status == None):
        return True
    print("Sendmail exit status", status)
    return False


def quanto_dormo():
    ''' Eseguo il test solo in orario lavorativo'''
    logging.info('entro nella funzione quanto_dormo')
    
    VENERDI = 5
    LUNEDI = 0
    
    # valore di default sleep
    sleep = 1
    
    now = datetime.datetime.now()
    if (now.weekday() > VENERDI):
        logging.warning(' FESTIVO')
        next_monday = datetime.timedelta((LUNEDI-now.weekday()) % 7)
        next_start = datetime.datetime(now.year, now.month, now.day, ORA_START, 0, 0) + next_monday
        secs = int(next_start.strftime('%s')) - int(now.strftime('%s'))
        logging.warning(" siamo nel finesettimana!! se vedemo tra %d secondi" % secs)
        sleep = secs
    elif (now.hour < ORA_START or now.hour > ORA_STOP):
        logging.warning(' ORARIO NON LAVORATIVO')
        
        # Calcolo se devo ripartire oggi o domani
        if (now.hour < ORA_START): 
            logging.warning('  Ci vediamo tra qualche ora')
            domani = 0
        elif (now.hour > ORA_STOP):
            logging.warning('  Ci vediamo domani')
            domani = 1
           
        next_start = datetime.datetime(now.year, now.month, now.day, ORA_START, 0, 0) + datetime.timedelta(domani)
        secs = int(next_start.strftime('%s')) - int(now.strftime('%s'))
        logging.warning(" e' tardi!! se vedemo tra %d secondi" % secs)
        sleep = secs
    else:
        logging.info(' ORARIO LAVORATIVO')
    return sleep


def netstat():
    ''' Controlla lo stato attuale del sistema in base al routing '''
    logging.info('entro nella funzione netstat')
    global ADSL
    global HDSL
    
    ADSL_ROUTE = 0
    HDSL_ROUTE = 0
    CMD='./netstat.sh'

    #netstat = ['DEFAULT=192.168.1.2 VPN=192.168.1.2'] # TEST
    netstat = os.popen(CMD).readlines()
    netstat = netstat[0].split(' ')

    for i in netstat:
        net_split = i.split('=')
        if (net_split[1] == ADSL['ip']):
            ADSL_ROUTE += 1
        elif (net_split[1] == HDSL['ip']):
            HDSL_ROUTE += 1
        else:
            logging.error(' ERROR!! %s non contemplato' % ('='.join(net_split)))
            sys.exit(1)

    if (ADSL_ROUTE == 0 and HDSL_ROUTE == len(netstat)):
        logging.info(' situazione attuale: SOLO_HDSL')
        return('SOLO_HDSL')
    elif (ADSL_ROUTE == len(netstat) and HDSL_ROUTE == 0):
        logging.info(' situazione attuale: SOLO_ADSL')
        return('SOLO_ADSL')
    else:
        logging.info(' situazione attuale: BILANCIATO')
        return('BILANCIATO')

def instrada(command):
    logging.debug('entro nella funzione instrada')
    global VPN
    global HDSL
    global ADSL
    
    ROUTE = []
    SEND = {}
    
    if (command == 'SOLO_HDSL'):
        logging.warning(' comando: %s in esecuzione' % command)
        ROUTE.append('route del default %s && route add default %s' % (ADSL['ip'], HDSL['ip']))
        ROUTE.append('route del -host %s %s && route add -host %s %s' % (VPN['ip'], ADSL['ip'], VPN['ip'], HDSL['ip']))
        ROUTE.append('route del -host %s %s && route add -host %s %s' % (VOIP['ip'], ADSL['ip'], VOIP['ip'], HDSL['ip']))
        SEND['TO'] = ADMIN_EMAIL 
        SEND['SUBJECT'] = 'Autorouting => HDSL - %s' % LOC
        CB_PROCEDURE = 'https://cb.schema31.it/cb/wiki/171638'
        SEND['TEXT'] = 'ADSL di %s non funziona, provvedo a migrare tutto il traffico su HDSL'\
                       '\n\n Vai qui:\n %s\n Per la procedura di segnalazione ' % (LOC, CB_PROCEDURE)
        
    elif (command == 'SOLO_ADSL'):
        logging.warning(' comando: %s in esecuzione' % command)
        ROUTE.append('route del default %s && route add default %s' % (HDSL['ip'], ADSL['ip']))
        ROUTE.append('route del -host %s %s && route add -host %s %s' % (VPN['ip'], HDSL['ip'], VPN['ip'], ADSL['ip']))
        ROUTE.append('route del -host %s %s && route add -host %s %s' % (VOIP['ip'], HDSL['ip'], VOIP['ip'], ADSL['ip']))
        SEND['TO'] = ADMIN_EMAIL 
        SEND['SUBJECT'] = 'Autorouting => ADSL - %s' % LOC
        CB_PROCEDURE = 'https://cb.schema31.it/cb/wiki/171639'
        SEND['TEXT'] = 'HDSL di %s non funziona, provvedo a migrare tutto il traffico su ADSL'\
                       '\n\n Vai qui:\n %s\n Per la procedura di segnalazione ' % (LOC, CB_PROCEDURE)

    elif (command == 'BILANCIATO'):
        logging.warning(' comando: %s in esecuzione' % command)
        ROUTE.append('route del default %s && route add default %s' % (HDSL['ip'], ADSL['ip']))
        ROUTE.append('route del -host %s %s && route add -host %s %s' % (VPN['ip'], ADSL['ip'], VPN['ip'], HDSL['ip']))
        ROUTE.append('route del -host %s %s && route add -host %s %s' % (VOIP['ip'], ADSL['ip'], VOIP['ip'], HDSL['ip']))
        SEND['TO'] = ADMIN_EMAIL 
        SEND['SUBJECT'] = 'Autorouting => BILANCIATO - %s' % LOC
        SEND['TEXT'] = 'La situazione sembra essere tornata normale su %s, provvedo a bilanciare il routing' %LOC
              
    elif (command == 'NON FACCIO NIENTE'):
        logging.info(' comando: %s in esecuzione' % command)
        return 0
    else:
        logging.error(' comando %s non supportato' % command)
        return 1
  
    # Operazioni effettive
    if (len(ROUTE) > 0):
        for R in ROUTE:
            logging.warning(R)
            route_out = os.popen(R).readlines()
            logging.info(route_out)
        sendMail(SEND['TO'], 'sysadmin@schema31.it', SEND['SUBJECT'], SEND['TEXT'])
        

def inc_quality(v,q, ulimit=10, llimit=-10):
    ''' Incrementa o decrementa il valore di Qualita' di collegamento '''
    logging.info('entro nella funzione inc_quality')
    s = int(v) + int(q)
    if (s <= ulimit and s >= llimit):
        return s
    elif (s > ulimit):
        return ulimit
    elif (s < llimit):
        return llimit
    else:
        return 'ERROR'


def decidi(QH,QA,stato):
    ''' Decide se cambiare il routing oppure no '''
    logging.info('entro nella funzione decidi')
    ret = 'NON FACCIO NIENTE'
    if (stato == 'BILANCIATO'):
        if (QH >= 5 and QA <= -5):
            ret = 'SOLO_HDSL'
        elif (QA >= 5 and QH <= -5):
            ret = 'SOLO_ADSL'
    elif (stato == 'SOLO_ADSL'):
        if (QH >= 5):
            ret = 'BILANCIATO'
    elif (stato == 'SOLO_HDSL'):
        if (QA >= 5):
            ret = 'BILANCIATO'
    else:
        ret = 'STATO INDEFINITO'
    return ret


def ping_test():
    ''' ICMP test basato su scapy '''
    logging.info('entro nella funzione ping_test')
    global ADSL
    global HDSL
    
    # TODO: spostare nel conf
    ADSL_RESP = 0
    ADSL_UNRESP = 0
    HDSL_RESP = 0
    HDSL_UNRESP = 0

    # Numero di ping da fare 
    PING = 10

    for i in range(0,PING):
        try:
            # ADSL TEST
            A_resp = srp1(Ether(dst=ADSL['arp'])/IP(dst=ADSL['ping_dst'])/ICMP()/"X", timeout=3, verbose=0)
            if (A_resp and A_resp['ICMP'].type == 0 and A_resp['ICMP'].code == 0):
                ADSL_RESP += 1
                logging.debug('ADSL from %s, to %s => %s' % (ADSL['arp'], ADSL['ping_dst'], A_resp.summary()))
            else:
                ADSL_UNRESP += 1
                if (A_resp):
                    summary = A_resp.summary()
                else:
                    summary = 'Non disponibile'
                logging.warning(' ADSL from %s, to %s => %s' % (ADSL['arp'], ADSL['ping_dst'], summary))

            # HDSL TEST
            H_resp = srp1(Ether(dst=HDSL['arp'])/IP(dst=HDSL['ping_dst'])/ICMP()/"X", timeout=3, verbose=0)
            if (H_resp and H_resp['ICMP'].type == 0 and H_resp['ICMP'].code == 0):
                HDSL_RESP += 1
                logging.debug(' HDSL from %s, to %s => %s' % (HDSL['arp'], HDSL['ping_dst'], H_resp.summary()))
            else:
                HDSL_UNRESP += 1
                if (H_resp):
                    summary = H_resp.summary()
                else:
                    summary = 'Non disponibile'
                logging.warning(' HDSL from %s, to %s => %s' % (HDSL['arp'], HDSL['ping_dst'], summary))

        except Exception as e:
            logging.error('ping error =>  arp:%s ping_dst:%s' % (ADSL['arp'],ADSL['ping_dst']))
            logging.error('ping error =>  arp:%s ping_dst:%s' % (HDSL['arp'],HDSL['ping_dst']))
            logging.info(e.__doc__)
            logging.error(e.message)
            raise
        finally:
            time.sleep(1)
    
    PING_ERROR = '\n ADSL ping OK: %d - KO: %d\n HDSL ping OK: %d - KO: %d' % (ADSL_RESP, ADSL_UNRESP, HDSL_RESP, HDSL_UNRESP)
    if (ADSL_UNRESP + HDSL_UNRESP > 0):
        logging.error(PING_ERROR)
    else:
        logging.info(PING_ERROR)

    # Analisi della qualita' del ping
    # ADSL
    if ((ADSL_UNRESP * 100 / PING) >= ADSL['th']):
        logging.warning(' route verso ADSL MALE!!')
        ADSL['Q'] = inc_quality(ADSL['Q'], -1 * ADSL_UNRESP)
    else:
        logging.info(' route verso ADSL BENE')
        ADSL['Q'] = inc_quality(ADSL['Q'], +1 )

    # HDSL
    if ((HDSL_UNRESP * 100 / PING) >= HDSL['th']):
        logging.warning(' route verso HDSL MALE!!')
        HDSL['Q'] = inc_quality(HDSL['Q'], -1 * HDSL_UNRESP)
    else: 
        logging.info(' route verso HDSL BENE')
        HDSL['Q'] = inc_quality(HDSL['Q'], +1 )

    logging.warning("\n Qualita' ADSL (-10 <-> +10): %d\n Qualita' HDSL (-10 <-> +10): %d" % (ADSL['Q'],HDSL['Q']))


if __name__ == "__main__":
    import signal
    
    def signal_handler(signal, frame):
        logging.info('You pressed Ctrl+C!')
        os.remove(RUNFILE)
        sys.exit(0)    
    
    def check_pid(pid):        
        """ Check For the existence of a unix pid. """
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        else:
            return True

    
    #RUNFILE
    if (os.path.isfile(RUNFILE)):
        pid = int(open(RUNFILE, 'r').read())
        if (check_pid(pid)):
            logging.error("Script gia' in esecuzione: %s con pid %d" % (RUNFILE,pid))
            sys.exit(1)

    runfile = open(RUNFILE, 'w')
    runfile.write(str(os.getpid()))
    runfile.close()
    
    #Ctrl + C handler
    signal.signal(signal.SIGINT, signal_handler)
    #print('Press Ctrl+C per stoppare lo script')

    # Ciclo infinito
    count = 0
    while True:
        logging.warning('\n\n ***** START *****')
        count += 1
        
        dormo = quanto_dormo()
        logging.info("Mi faccio una dormitina di %d secondi" % dormo)
        time.sleep(dormo)
        
        stato_routing = netstat()
        
        ping_test()
        
        decisione = decidi(QH=HDSL['Q'],QA=ADSL['Q'],stato=stato_routing)
        
        # Instrado solo dopo aver acquisito almeno 15 campioni
        if (count > 5):
            instrada(decisione)
        else:
            logging.info("non instrado in quanto i campioni non sono ancora sufficienti, campioni: %d" % count)
        
        if (HDSL['Q'] >= 10 and ADSL['Q'] >= 10):
            pisolino = 60
            logging.info("Pare che la qualita' della linea sia ottima... mi concedo un pisolino di %d secondi" % pisolino)
            time.sleep(pisolino)

    logging.warning('\n\n ***** STOP *****')
    runfile = open(RUNFILE,'w')
    runfile.write('')
    runfile.close()