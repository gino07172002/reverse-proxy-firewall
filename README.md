### ssh -inrt fire wall


you have computerA with floating ip (192.168.1.203)

you have another computerB with fixed ip (192.168.1.222)

you use ssh Reverse proxy to make other computer by use this port

```
ssh -R 1234:localhost:22 gino@192.168.1.222
```

so other computer can ssh to computerA by computerB's port


```
ssh -p 1234 computerA@A's ip
```



### about this program

when this program launch , it would automatically set iptable rule to specific port

it would reset or drop the proxy package of client if not in whitelist
