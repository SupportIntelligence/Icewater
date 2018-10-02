
rule n26bb_1b9a9ec9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.1b9a9ec9cc000b12"
     cluster="n26bb.1b9a9ec9cc000b12"
     cluster_size="789"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="riskware cocvs score"
     md5_hashes="['7e1c2a6c4cbfd3988db25e4a2aaaafeb3878b27d','454e341f97513c0a2bf010d5b9d1eac20a1b8633','290bbad5569d6020fdc6a45af613b2afdff4ea45']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.1b9a9ec9cc000b12"

   strings:
      $hex_string = { f69c16294d19c148de4c7aa08cc822897033950d77dd2899ec6fcb37786e348640eb1282dafb25211cf3c281089eb797b55c03353b7fb4e3f87532ba47e688b3 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
