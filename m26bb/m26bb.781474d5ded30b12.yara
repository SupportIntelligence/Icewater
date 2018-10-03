
rule m26bb_781474d5ded30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.781474d5ded30b12"
     cluster="m26bb.781474d5ded30b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="explorerhijack aerlywji malicious"
     md5_hashes="['65a949d4be0d75df847bbffa7bc42c81914faf0a','b94ded606262f3e72c842d4ee79aec4216b81f98','eae6ccb5bda971e8ae85888a8a200c3bb58753c9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.781474d5ded30b12"

   strings:
      $hex_string = { 01c351b8d34d6210f7e1535556578bfac1ef068bc769c0e80300002bc8740383c7018b2dcc50400032db885c241333f68bff807c241300752c3bf77328e830fd }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
