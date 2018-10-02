
rule m26d7_39a5694140000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26d7.39a5694140000932"
     cluster="m26d7.39a5694140000932"
     cluster_size="1054"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="adload xetapp attribute"
     md5_hashes="['47541420dff831ba7d1266afe635eb6db6b386be','d346bdab49a003b47e7c3c68e4ee7df30da6ae58','8a4b5ad29788037b007d0e1cfbbc7db75d8f5762']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26d7.39a5694140000932"

   strings:
      $hex_string = { eb3583c00a51516879b6400050e84afeffff89c35885db5a89f0741b8d14378b45ec8d0c02eb068a024a8841014939da77f529fb8d4301ff75ec8d040768c82f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
