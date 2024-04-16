# 毕设 from njust 0237 on99 mielma

```
0.BASE PART::
    -h --help                   Show this help message and exit
    -ip --ipaddress             Specify the broker address (defaults to <127.0.0.1>)
    -p --port                   Specify the broker port (defaults to <1883>)
    -i --interface              Specify the broker interface (defaults to <sns>)
    -mv --mqttversion           Specify the broker mqtt version (defaults to <5>)
    -st --subtopic              Specify the broker mqtt subscribe topic (defaults to <test/#>)
    -pts --pubtopicsuffix       Specify the broker mqtt publish topic suffix (defaults to <test/>)
    -cids --clientidsuffix      Specify the broker mqtt publish topic suffix (defaults to <mqtt_>)
1.ADVANCED PART::
 >1.1 SCAPY PART::
   >>s                         Specify using scapy
    -f --flood                  Specify using flood attack
    -m --mitm                   Specify using mitm attack
    -e --editmsg                Specify using mitm attack and specify msg (defaults to <''>)
    -fz --fuzz                  Specify using fuzzing attack
 >1.2 PAHO2 PART::
   >>p                         Specify using paho2
    -f --flood                  Specify using flood attack
    -ez --ezflag                Specify using easy flood attack or not (defaults to <True/Yes>)
    -m --mitm                   Specify using mitm attack
    -e --editmsg                Specify using mitm attack and specify msg (defaults to <''>)
    -sd --slowdos               Specify using slow dos attack
    -c --count                  Specify using slow dos attack and specify connections count(defaults to <3000>)
    -b --bruteforce             Specify using brute force attack
 >1.3 DETECT PART::
   >>d                         Specify using detect mode
    -b --bruteforce             Specify detect brute force attack
    -fz --fuzz                  Specify detect fuzzing attack
    -f --flood                  Specify detect flood attack
 >1.4 UTILS PART::
   >>u                         Specify using some utils
    -gi --getiface              CHECKING ALL INTERFACE ON THIS DEVICE
```

