
rule n26c9_6b99b561ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26c9.6b99b561ca000b12"
     cluster="n26c9.6b99b561ca000b12"
     cluster_size="578"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="runbooster malicious susp"
     md5_hashes="['2fe1859fa14d869d600147a12c6fc98a9cb2d73f','627bb6433b76101a923763fb89c63ad7cce96c6a','7108d76a9e03c9e9ed3b181577c8f961774c6903']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26c9.6b99b561ca000b12"

   strings:
      $hex_string = { 574883ec200fb6da488bf9488b11483b5110747d448b49704c8d4202488b496841c1e9084180e101e8791900000fb7f06685c0745c84db7409488d4f40e81406 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
