
rule k26bb_4b366da1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.4b366da1c4000b12"
     cluster="k26bb.4b366da1c4000b12"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="virut malicious patched"
     md5_hashes="['1bb44a330eaa2dcd6c3c3be79a017b4ec0280be3','73d4c9e9cc6a0cbe7df27d06fa63edcc07d57394','72e9baa173fb358e79a3b7e948c6b30a100ee555']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.4b366da1c4000b12"

   strings:
      $hex_string = { 3902740542424e75f63bf07507b857000780eb0b8b55103bd074042bce890a5e5dc20c00cccccccccc8bff558bec568b750856ff155810000166833e22752166 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
