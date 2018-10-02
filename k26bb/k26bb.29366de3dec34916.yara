
rule k26bb_29366de3dec34916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.29366de3dec34916"
     cluster="k26bb.29366de3dec34916"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="installcore unwanted core"
     md5_hashes="['d3a762d722325eee886c4f62fe9e0fb8f6374730','e3a76a7ea7402ec8907d038cda7c74c365f68929','3286482337524c66a5f4ec715115f03321cbff03']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.29366de3dec34916"

   strings:
      $hex_string = { 2cb1af5deecd4bc5d94c99893f2b0708354d17c9dadd7d56506504cb83f9c69bc1c7243cbe7b01f3e7ca880da9258687e1639695ccaa9a5bb71badecd75e6a8a }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
