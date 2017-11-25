
rule j3f7_299d92c9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f7.299d92c9c4000b12"
     cluster="j3f7.299d92c9c4000b12"
     cluster_size="3"
     filetype = "text/plain"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="script expkit html"
     md5_hashes="['870bd64996f2ce4f37654f551d5e6480','9dbe72268e59e43b03a2b5578feeda6a','fdaf6c7570c44def896d726966163197']"

   strings:
      $hex_string = { 3d200d0a2827303132333435363738394142434445464748494a4b4c4d4e4f5051525354555658595a6162636465666768696a6b6c6d6e6f7071727374757678 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
