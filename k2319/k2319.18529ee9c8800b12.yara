
rule k2319_18529ee9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.18529ee9c8800b12"
     cluster="k2319.18529ee9c8800b12"
     cluster_size="23"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script expkit"
     md5_hashes="['24c2289bf3b7b394c636089b9cc4a338ad42686a','759eda2171cd1caf7cd50376707d0b90ba810542','ea32c7f1a40222cbf7b4b2d6d321aed210b78654']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.18529ee9c8800b12"

   strings:
      $hex_string = { 3c2834312e2c32392e293f31302e373145323a283078452c332e38384532292929627265616b7d3b766172204a37633d7b2756384d273a2237222c2742363927 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
