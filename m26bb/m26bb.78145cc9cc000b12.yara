
rule m26bb_78145cc9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.78145cc9cc000b12"
     cluster="m26bb.78145cc9cc000b12"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="explorerhijack aszctebi malicious"
     md5_hashes="['4cc2fbe699916a6e93ccbe206deb99851314a3c4','8f1ce703554fc66ab9facbc219c321115d2479a7','de3f76ec3e9eeac2575991284c2d7f966fe01bd9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.78145cc9cc000b12"

   strings:
      $hex_string = { 01c351b8d34d6210f7e1535556578bfac1ef068bc769c0e80300002bc8740383c7018b2dcc50400032db885c241333f68bff807c241300752c3bf77328e830fd }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
