#!/sbin/sh
  ui_print " "
  ui_print "*******************************"
  ui_print "*    Magisk Module NFQTTL     *"
  ui_print "*        Version 2.8          *"
  ui_print "*******************************"
  ui_print " "

  APP_ABI=$(getprop ro.product.cpu.abi)
  ui_print " APP_ABI: $APP_ABI "
  ui_print " "
  ui_print " unzip "
  ui_print " "

  if [ -f "$MODPATH/libs/$APP_ABI/nfqttl" ]; then
    ui_print " Copying binary for $APP_ABI! "
    ui_print " "
    cp -afv $MODPATH/libs/$APP_ABI/nfqttl $MODPATH/nfqttl
    rm -rf $MODPATH/libs
  else
    abort " Binary file for $APP_ABI is missing! Abort installing! "
  fi


  pkill -9 nfqttl
  cd $MODPATH
  chmod 755 nfqttl
  if ./nfqttl -d -s -u ; then
    ui_print " "
    ui_print " Run nfqttl success! "
    ui_print " "
  else
    abort " Run nfqttl fail. Abort installing! "
    ui_print " "
  fi

  iptables -t mangle -D PREROUTING -j nfqttli
  iptables -t mangle -D OUTPUT -j nfqttlo

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
    iptables -t mangle -A nfqttli -j NFQUEUE --queue-num 6464 &&\
    iptables -t mangle -N nfqttlo &&\
    iptables -t mangle -A nfqttlo -j NFQUEUE --queue-num 6464 &&\
    iptables -t mangle -A PREROUTING -j nfqttli &&\
    iptables -t mangle -A OUTPUT -j nfqttlo &&\
    ip6tables -t mangle -N nfqttli &&\
    ip6tables -t mangle -A nfqttli -j NFQUEUE --queue-num 6464 &&\
    ip6tables -t mangle -N nfqttlo &&\
    ip6tables -t mangle -A nfqttlo -j NFQUEUE --queue-num 6464 &&\
    ip6tables -t mangle -A PREROUTING -j nfqttli &&\
    ip6tables -t mangle -A POSTROUTING -j nfqttlo \
  ; then
    ui_print " Set rule iptables success! "
    ui_print " "
  else
    abort " Set rule iptables fail. Abort installing! "
  fi


  set_perm $MODPATH/nfqttl 0 0 0755
  set_perm $MODPATH/service.sh 0 0 0755
  ui_print " "
  ui_print "*******************************"
  ui_print "*      Install Success!       *"
  ui_print "*******************************"
  ui_print " "
