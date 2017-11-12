
rule m3e9_259563a9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.259563a9ca000b12"
     cluster="m3e9.259563a9ca000b12"
     cluster_size="551"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus sirefef malicious"
     md5_hashes="['01db9a7a84b854f920de5c0a975b7374','02935d174bd4ca3a9bf793c14ae9130e','151fb429f02d31fa53b11c8a89b13b4f']"

   strings:
      $hex_string = { 00d58b8b00d38d8d00d58d8d00d88e8e00cf919100d0939300d9919100dd949400df999900e1979700cf9ca300cca7a700ccada500c7a5a900d3a7a700d8a3a3 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
