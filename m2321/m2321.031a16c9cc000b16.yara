
rule m2321_031a16c9cc000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.031a16c9cc000b16"
     cluster="m2321.031a16c9cc000b16"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['2382d13ad50acbce0a966679d55b3ce1','376a07e2bc9acd0aa365f0f4cdac7319','fbfee8fa18289e55e7e297c0c0dbc9ca']"

   strings:
      $hex_string = { c6412289a9456b791c01f157d927829467939fd53c43f0460fb2eae983967a2c612faa488b391034d071a4661fb35395def4b4c486ce265b864b78915d076a6f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
