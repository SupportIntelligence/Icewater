
rule nfc8_019ad7b9caa00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=nfc8.019ad7b9caa00b12"
     cluster="nfc8.019ad7b9caa00b12"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos banker smforw"
     md5_hashes="['0d6cecbbd706e3ad64bc08440126698b879f8a92','308079f3b90e1c4e50245d2e75742c893abe0e92','5060ae8ff7b137304f2a8320062db5558cfec2b4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=nfc8.019ad7b9caa00b12"

   strings:
      $hex_string = { d9d1ea83dc6ed829ecfdd622e6664ecd2a6c94bc216c56dbe7a9b860ab1bb3317ea68d8ee988f1e4901f5225ef59b604a3d22fb09dfca2ce98a575541196134b }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
