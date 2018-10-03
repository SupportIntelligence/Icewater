
rule n26bf_081ea259c6620b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bf.081ea259c6620b32"
     cluster="n26bf.081ea259c6620b32"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="msilperseus malicious attribute"
     md5_hashes="['dcbe501457398e4b83e37154b87296320a6aa6ae','d248d9bce85c417e2b341e792cc3204835dad649','c9ef58f20d8680bde3847ef48d422c096013867c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bf.081ea259c6620b32"

   strings:
      $hex_string = { 421fe1d52315cd1965612bb00c9ae77fbf691b07a18e4587e10556f74a5cfd2ce62e20557cdd9691a04b16600493cafcc000c7c1db49d4923536f0588da9acc4 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
