
rule i233f_54ba72c2b69744ba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i233f.54ba72c2b69744ba"
     cluster="i233f.54ba72c2b69744ba"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="efaff voiv expkit"
     md5_hashes="['8cd1f997c699fa18cf8a26670feecb52da8df8c6','07ba0116fc3ba8d3b7f9f13cab8b3164878f0368','09eb406971b4947514c2ef7e5fb2cdffc5683662']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=i233f.54ba72c2b69744ba"

   strings:
      $hex_string = { 002e0030002200200065006e0063006f00640069006e0067003d0022005500540046002d003100360022003f003e000d000a003c005400610073006b00200076 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
