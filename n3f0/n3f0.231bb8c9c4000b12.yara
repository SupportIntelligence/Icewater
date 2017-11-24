
rule n3f0_231bb8c9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f0.231bb8c9c4000b12"
     cluster="n3f0.231bb8c9c4000b12"
     cluster_size="15"
     filetype = "PE32 executable (GUI) Intel 80386 (stripped to external PDB)"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="mira bqcb malicious"
     md5_hashes="['0104e5e314bae907bd66687c550243e0','118285fe9acbfd9a1435020b9842a9f4','fb83a9f3a6b68bcf0bd92f766839cc42']"

   strings:
      $hex_string = { d0c1e00809c366891983e9024e0fb6de79ea0fb7450083c708f6c4ff74ce6685c0784a8b5c241c8d731089f689f131c0bb06000000eb1c908d74260001d2a802 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
