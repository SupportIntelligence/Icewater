
rule m26c9_111fa849c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26c9.111fa849c0000b12"
     cluster="m26c9.111fa849c0000b12"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="coinminer bitmin malicious"
     md5_hashes="['ad19d703f48a2ce6043835c3b415b02136cb7146','b5dcd438193a00ab3bfe8a8cf9635901577bbf7c','95bcc4799de564d9366f4a4ea2fa46a92c4ec497']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26c9.111fa849c0000b12"

   strings:
      $hex_string = { bae612730383cf10448b432033c90fb7f64585c07e214c8b4b08498bd10fb742023bf075070fb6023bf8742cffc14883c206413bc87ce6418d400133d2894320 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
