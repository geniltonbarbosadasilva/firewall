from netfilterqueue import NetfilterQueue

def print_and_accept(pkt):
    print("Here")
    print(pkt)
    pkt.accept()

nfqueue = NetfilterQueue()
nfqueue.bind(1, print_and_accept)

try:
    nfqueue.run()
except KeyboardInterrupt:
    print('KeyboardInterrupt')
except Exception as e:
    print(e)

nfqueue.unbind()