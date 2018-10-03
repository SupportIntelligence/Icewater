
rule n26bb_519e9cc1cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.519e9cc1cc000b32"
     cluster="n26bb.519e9cc1cc000b32"
     cluster_size="44"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="explorerhijack patched malicious"
     md5_hashes="['d6cb84c77852b4686e86c632e147fc7ac7c38fdd','5ee774b1ee733a2921f7789a715d845fc0b861eb','7d032946b47f77fb409bc89d14cc8b2361a7d1a1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.519e9cc1cc000b32"

   strings:
      $hex_string = { 01c351b8d34d6210f7e1535556578bfac1ef068bc769c0e80300002bc8740383c7018b2dcc50400032db885c241333f68bff807c241300752c3bf77328e830fd }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
