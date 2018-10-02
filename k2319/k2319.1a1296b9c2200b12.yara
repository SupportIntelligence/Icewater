
rule k2319_1a1296b9c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a1296b9c2200b12"
     cluster="k2319.1a1296b9c2200b12"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['b26d457955386e14e6fe8b95b2734deefe20d4d6','9ce07f2828d200e02f616f36dce667061a3674a2','92f502fd7d2dd7991c6231baffb16ec70473a0eb']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a1296b9c2200b12"

   strings:
      $hex_string = { 30783234312c3235292929627265616b7d3b666f72287661722064397420696e205432413974297b6966286439742e6c656e6774683d3d3d283131322e383045 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
