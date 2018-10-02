
rule k2319_11149699c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.11149699c2200b12"
     cluster="k2319.11149699c2200b12"
     cluster_size="18"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik diplugem script"
     md5_hashes="['24cf70e165b10d4ab1dc858d5f1dbf96122891c0','7cb86906a47797110f7886ec580c941d71c6b65b','f31a43014c368c8c524ece9d33a96a2fe02a0fd2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.11149699c2200b12"

   strings:
      $hex_string = { 36394532292929627265616b7d3b666f7228766172204a386820696e204735453868297b6966284a38682e6c656e6774683d3d3d2834333c283130372e2c3078 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
