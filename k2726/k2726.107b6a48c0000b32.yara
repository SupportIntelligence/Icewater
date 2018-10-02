
rule k2726_107b6a48c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2726.107b6a48c0000b32"
     cluster="k2726.107b6a48c0000b32"
     cluster_size="89"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="patched generickd malicious"
     md5_hashes="['0eb43e45a0e2cfaaa4a178b14a3d9ab3dcbf4c7c','e5a6c06a02691786fbc838f88d91895cb488661d','d30abdc7d09f50c8b36dceb26567466e0fb6b7f0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2726.107b6a48c0000b32"

   strings:
      $hex_string = { 6510027452a1f045ba7733d2eb258b480c894c95bc33ff8b8fa045ba773bcb74073901750389511883c70483ff4072e78b00423bc375d768000003005368d023 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
