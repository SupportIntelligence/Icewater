
rule k26bb_46cda166cce30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.46cda166cce30b12"
     cluster="k26bb.46cda166cce30b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="explorerhijack aurrtjdi malicious"
     md5_hashes="['6d11fcddbca77fa06e9014b435250c0296ac164b','23fbf12814c0ccb0ec23bde008e070027532b7a1','2f0d7d9430ece77e5037557e8ca6101a092b3ca7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.46cda166cce30b12"

   strings:
      $hex_string = { 01c351b8d34d6210f7e1535556578bfac1ef068bc769c0e80300002bc8740383c7018b2dcc50400032db885c241333f68bff807c241300752c3bf77328e830fd }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
