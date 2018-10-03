
rule k26bb_46cda166c58bdb12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.46cda166c58bdb12"
     cluster="k26bb.46cda166c58bdb12"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="explorerhijack aotl malicious"
     md5_hashes="['8c68e3a9f94a596472927e5836851c06549e6ca5','283c55c40d2a4ec6e0e61e3cb1ef47635bd44159','21fd13a9758a3e67128c5c3960d24a492914d765']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.46cda166c58bdb12"

   strings:
      $hex_string = { 01c351b8d34d6210f7e1535556578bfac1ef068bc769c0e80300002bc8740383c7018b2dcc50400032db885c241333f68bff807c241300752c3bf77328e830fd }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
