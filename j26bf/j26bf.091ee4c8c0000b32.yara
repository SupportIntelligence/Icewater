
rule j26bf_091ee4c8c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26bf.091ee4c8c0000b32"
     cluster="j26bf.091ee4c8c0000b32"
     cluster_size="359"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="zusy starter malicious"
     md5_hashes="['3b4d193bd108fe8e8209d473f25cd50eb7b7a721','60ef3ffe46b3993a7859b053541192545e2f6613','dcceb638cdbd43999ff7e7a0ee6742b135b355be']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26bf.091ee4c8c0000b32"

   strings:
      $hex_string = { 734f626a65637450726f7669646572004170706c69636174696f6e00576562536572766963657300457175616c73006f0047657448617368436f646500547970 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
