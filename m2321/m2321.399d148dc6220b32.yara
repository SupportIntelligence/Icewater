
rule m2321_399d148dc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.399d148dc6220b32"
     cluster="m2321.399d148dc6220b32"
     cluster_size="10"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['1f9961d9315922d82bca5ed510122cc3','37aaadddd067a3aff1deb8cf48f23e45','f6aa5133cd4208a2e95985f7ee905dce']"

   strings:
      $hex_string = { 5b86c7637f327d9eccea904a0a288450effeb4720d6b108c3437f7b685aa70b35400a5a8c59f171fe902db91e5ed0fdd1213faf61e59d558244dd180bf512de3 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
