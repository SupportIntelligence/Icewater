
rule k26bb_6ec09ce9354866f2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.6ec09ce9354866f2"
     cluster="k26bb.6ec09ce9354866f2"
     cluster_size="24"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="mywebsearch mindspark malicious"
     md5_hashes="['0c08c6dcb67d9a9070a8f16d4c1275c56b864d82','c35bee0201beee461976ed7f79c1e5a47caa0f19','391ecdab91a1399a9f0ba503e1dbc88567c992cb']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.6ec09ce9354866f2"

   strings:
      $hex_string = { d080e201f6da1bd281e22083b8edd1e833c24e75ea89048d981843004181f9000100007cd58b5424108b44240885d2f7d076238b4c240c570fb6398bf081e6ff }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
