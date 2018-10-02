
rule n26bb_4b1a16a1ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.4b1a16a1ca000b12"
     cluster="n26bb.4b1a16a1ca000b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dealply malicious applicunwnt"
     md5_hashes="['4138a9b50aae9675fa3c091c0ca8a6c2b94c05f2','b39cc413efb55ffaaadfe8ad8ee5b1d34472ea53','45f1d2c74ad725858f11fedf04a38683727fba2d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.4b1a16a1ca000b12"

   strings:
      $hex_string = { de203934b82f044279ffcfc4da37d02f57cc64ffe81466bfd9f707506f699272005bfcef4361562ab3f9dd6bf6055f00ef18111005cad76dee36341df1017f3f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
