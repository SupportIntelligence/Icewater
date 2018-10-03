
rule k2318_7719a6b9caa00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.7719a6b9caa00b12"
     cluster="k2318.7719a6b9caa00b12"
     cluster_size="49"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe redirector html"
     md5_hashes="['89ecc077a4f129b8d59a46c5267d8bafba05af00','fc947d365abbd121a73e97fa9b86b51fdfc5de80','e4322263b7531d5076b4b4d010da0d18ac591cc6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.7719a6b9caa00b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
