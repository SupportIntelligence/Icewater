
rule m3e9_49947849c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.49947849c8000b12"
     cluster="m3e9.49947849c8000b12"
     cluster_size="13"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob malicious"
     md5_hashes="['0270ace6f404dfd48c494059008c7a2d','1d615b1995eeb63bcc0a3d6b3034920b','fc89e9f7cf1cdc046a163b5ef5b4d783']"

   strings:
      $hex_string = { 726e6574204e657773204d6573736167655c44656661756c7449636f6e222c2c3133313037322c22255359535f4d4f445f50415448252c2d35220d0a484b4352 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
