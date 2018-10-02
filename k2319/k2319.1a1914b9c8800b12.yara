
rule k2319_1a1914b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a1914b9c8800b12"
     cluster="k2319.1a1914b9c8800b12"
     cluster_size="22"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['d0383196fdc7aeb86f90a71569cc22f1716bc9ab','bb5e994ff1c4c6967a61d49f29a0455ddec4b154','db400dcbd8eaff70dfdc5f95802ef7285b1d9a45']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a1914b9c8800b12"

   strings:
      $hex_string = { 30784335292929627265616b7d3b7661722074306e31483d7b275a3671273a226574222c274a3271273a227b222c274c3968273a66756e6374696f6e284d2c51 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
