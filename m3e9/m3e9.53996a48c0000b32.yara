
rule m3e9_53996a48c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.53996a48c0000b32"
     cluster="m3e9.53996a48c0000b32"
     cluster_size="7"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy carberp"
     md5_hashes="['3dba8cfbc70e04df512bd0df4d65c4a0','6984b31afad5825a8d4246daafa2ecc0','f980f505459b18611279f91b05dab9b2']"

   strings:
      $hex_string = { d5d37b82c98beebb152eefe9cf2661dd2364f0ba3b36cd1cf6a95191acf1bc7c4b32104535858ee7b7f286420ee0b3e330476f5529d24d09d9c4f981d07e2a41 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
