
rule n26bb_4b1a14e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.4b1a14e9c8800b12"
     cluster="n26bb.4b1a14e9c8800b12"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dealply malicious dmzar"
     md5_hashes="['25e038246b188e7cb7f1b1db1771c11ad3d071db','dcaf50cace7eaf9e485b143e953ec8bff4ffe727','d01b58d4b2045933d0ba2c5d1adac4a3a6adf17d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.4b1a14e9c8800b12"

   strings:
      $hex_string = { de203934b82f044279ffcfc4da37d02f57cc64ffe81466bfd9f707506f699272005bfcef4361562ab3f9dd6bf6055f00ef18111005cad76dee36341df1017f3f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
