from ubuntu:18.04
run apt-get update && apt-get install -y xinetd libssl1.0.0 netcat.openbsd

run mkdir /tania && chmod 755 /tania && chown root:root /tania

copy data/flag /tania/flag
copy data/privkey /tania/privkey
run chmod 444 /tania/flag && chown root:root /tania
run chmod 444 /tania/privkey && chown root:root /tania
copy tania /tania/tania
run chmod 555 /tania/tania

copy tania.conf /etc/xinetd.d/tania.conf
run chmod 440 /etc/xinetd.d/tania.conf

copy wrapper /opt/wrapper
run chmod 555 /opt/wrapper
copy schitzo /opt/schitzo
run chmod 555 /opt/schitzo
run chmod 551 /opt

run chmod 773 /tmp/

expose 5000
cmd chmod 550 /proc && /usr/sbin/xinetd -filelog - -dontfork -f /etc/xinetd.d/tania.conf
