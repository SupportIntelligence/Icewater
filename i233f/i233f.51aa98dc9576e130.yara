
rule i233f_51aa98dc9576e130
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i233f.51aa98dc9576e130"
     cluster="i233f.51aa98dc9576e130"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="voiv expkit html"
     md5_hashes="['c31d5b7db6c13ede1537096ac81c2f29c28edaf4','6f0f9b058bf9005654636629d47e31808e1cef1a','4cdc486ce694c34664e37f896d70d8a0a9097b76']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=i233f.51aa98dc9576e130"

   strings:
      $hex_string = { 002e0030002200200065006e0063006f00640069006e0067003d0022005500540046002d003100360022003f003e000d000a003c005400610073006b00200076 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
