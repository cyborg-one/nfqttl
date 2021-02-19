#!/sbin/sh
  ui_print " "
  ui_print "*******************************"
  ui_print "*    Magisk Module NFQTTL     *"
  ui_print "*        Version 2.7          *"
  ui_print "*******************************"
  ui_print " "

  APP_ABI=$(getprop ro.product.cpu.abi)
  ui_print " APP_ABI: $APP_ABI "
  ui_print " unzip "

  ui_print " Check ip_tables_targets "
  if [ -f "$MODPATH/libs/$APP_ABI/nfqttl" ]; then
    ui_print "* Copying binary for $APP_ABI!"
    cp -afv $MODPATH/libs/$APP_ABI/nfqttl $MODPATH/nfqttl
    rm -rf $MODPATH/libs
  else
    abort "Binary file for $APP_ABI is missing! Abort installing!"
  fi


  pkill -9 nfqttl
  cd $MODPATH
  chmod 755 nfqttl
  if ./nfqttl -d -s4 ; then
    ui_print "Run nfqttl success!"
  else
    abort "Run nfqttl fail. Abort installing!"
  fi

  iptables -t mangle -D PREROUTING -j nfqttli
  iptables -t mangle -D POSTROUTING -j nfqttlo

  iptables -t mangle -F nfqttli
  iptables -t mangle -X nfqttli

  iptables -t mangle -F nfqttlo
  iptables -t mangle -X nfqttlo

  ip6tables -t mangle -D PREROUTING -j nfqttli
  ip6tables -t mangle -D POSTROUTING -j nfqttlo

  ip6tables -t mangle -F nfqttli
  ip6tables -t mangle -X nfqttli

  ip6tables -t mangle -F nfqttlo
  ip6tables -t mangle -X nfqttlo


  if iptables -t mangle -N nfqttli &&\
     iptables -t mangle -A nfqttli -m mark --mark 0x10000001 -j RETURN &&\
     iptables -t mangle -A nfqttli -m mark --mark 0x10000002 -j RETURN &&\
     iptables -t mangle -A nfqttli -j NFQUEUE --queue-num 0x1000 &&\
     iptables -t mangle -A PREROUTING -j nfqttli &&\
     iptables -t mangle -N nfqttlo &&\
     iptables -t mangle -A nfqttlo -m mark --mark 0x10000001 -j RETURN &&\
     iptables -t mangle -A nfqttlo -m mark --mark 0x10000003 -j RETURN &&\
     iptables -t mangle -A nfqttlo -j NFQUEUE --queue-num 0x1000 &&\
     iptables -t mangle -I POSTROUTING -j nfqttlo &&\
     ip6tables -t mangle -N nfqttli &&\
     ip6tables -t mangle -A nfqttli -m mark --mark 0x10000001 -j RETURN &&\
     ip6tables -t mangle -A nfqttli -m mark --mark 0x10000002 -j RETURN &&\
     ip6tables -t mangle -A nfqttli -j NFQUEUE --queue-num 0x1000 &&\
     ip6tables -t mangle -A PREROUTING -j nfqttli &&\
     ip6tables -t mangle -N nfqttlo &&\
     ip6tables -t mangle -A nfqttlo -m mark --mark 0x10000001 -j RETURN &&\
     ip6tables -t mangle -A nfqttlo -m mark --mark 0x10000003 -j RETURN &&\
     ip6tables -t mangle -A nfqttlo -j NFQUEUE --queue-num 0x1000 &&\
     ip6tables -t mangle -I POSTROUTING -j nfqttlo ; then
    ui_print "Set rule iptables success!"
  else
    abort "Set rule iptables fail. Abort installing!"
  fi


  set_perm $MODPATH/nfqttl 0 0 0755
  set_perm $MODPATH/service.sh 0 0 0755
  ui_print " "
  ui_print "*******************************"
  ui_print "*      Install Success!       *"
  ui_print "*******************************"
  ui_print " "
