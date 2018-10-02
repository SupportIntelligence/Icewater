
rule k2319_1a0896b9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a0896b9c8800912"
     cluster="k2319.1a0896b9c8800912"
     cluster_size="26"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['e6606e55a8f31452a486a26f1b1d3ee67d961331','66f8d5f2b9f27c8ff73dd89319ada8cf3be863cc','c97a96820bd5cf27bc976a6ead6351cfff013bec']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a0896b9c8800912"

   strings:
      $hex_string = { 66696e6564297b72657475726e20485b515d3b7d766172206f3d282836372e2c352e33304531293c3d2832322e3645312c3134332e394531293f28382c307863 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
