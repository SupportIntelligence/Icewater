
rule m26bb_3cb330c344000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.3cb330c344000b32"
     cluster="m26bb.3cb330c344000b32"
     cluster_size="474"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="zusy malicious backdoor"
     md5_hashes="['efd042f33a055b77f3a0d231f1a31b2bf00b1147','e572253c09ae81219a723cd15fbe88e737e9513d','a256bcf81ccc922ef9022b23bfa83e3953c38b19']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.3cb330c344000b32"

   strings:
      $hex_string = { 0080c12a688096980081d1214e62fe5150e81737000083fa077c0e7f073dff6f4093760583c8ff8bd08b4d0885c974058901895104c9c3c70150c24000e91038 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
