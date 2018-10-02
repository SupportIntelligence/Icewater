
rule k2319_1e1296b9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1e1296b9c8800b32"
     cluster="k2319.1e1296b9c8800b32"
     cluster_size="31"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['1e55492412ef32757b8b700acc1c761acf48ad8f','e161830bda2b326ecd1b9d543858bf48cdd136f0','3af7a001970a4257b4c8a386d6cf11d17ef69119']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1e1296b9c8800b32"

   strings:
      $hex_string = { 4232293f28307846322c313139293a2831332c30783637292929627265616b7d3b7661722072304c303d7b2745384a273a2258222c276f30273a66756e637469 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
