
rule n26c0_33128084da63d932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26c0.33128084da63d932"
     cluster="n26c0.33128084da63d932"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="generickdz malicious kryptik"
     md5_hashes="['12b881fc871ac5b07c8424e45ea035213cc5dcce','25d8f78ecf48f980fad8614052f6f271e3927fba','eaf0faa61053bc2305d69d7cd7646556edae73a5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26c0.33128084da63d932"

   strings:
      $hex_string = { 8d46185750e895c3ffff895e0483c40c33db89be1c02000043395de87651807dee008d45ee74218a480184c9741a0fb6d10fb608eb06804c0e1904413bca76f6 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
