import "hash"

rule p3e9_13195ec1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=p3e9.13195ec1cc000b12"
     cluster="p3e9.13195ec1cc000b12"
     cluster_size="665 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ircbot backdoor dorv"
     md5_hashes="['2a723f8ccb98030072f02e1f1931055a', 'b215df0856200e83fc44f96edf54270c', '04af160ffe5b30b9b8b8bdf953a8958f']"


   condition:
      filesize > 4194304 and filesize < 16777216
      and hash.md5(79788,1030) == "d3e5be795e3c1744053621665c7c209d"
}

