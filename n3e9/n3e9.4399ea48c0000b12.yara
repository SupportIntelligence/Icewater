
rule n3e9_4399ea48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4399ea48c0000b12"
     cluster="n3e9.4399ea48c0000b12"
     cluster_size="183"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus sirefef jorik"
     md5_hashes="['049a7ba53757afd11b97c2b4976e4187','0a02ef92df8414a62f0c94d17c57c14c','62d88abc5c5c2f0b68820e4a282d86c4']"

   strings:
      $hex_string = { 000000833dd0f8430000751b68d0f84300687c6d4000e8e48cfcffc7851cfaffffd0f84300eb0ac7851cfaffffd0f843008b851cfaffff8b008985b8fcffff8d }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
