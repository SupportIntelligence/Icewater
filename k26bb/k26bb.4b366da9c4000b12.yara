
rule k26bb_4b366da9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.4b366da9c4000b12"
     cluster="k26bb.4b366da9c4000b12"
     cluster_size="48"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="virtob virut malicious"
     md5_hashes="['e5e896342236cddf7cf7f28322104da5a0656cd0','7f1e77a9b195e4757853e6fec9607f1a368fa295','50703c6ebcb5dfbd089ef66117a6bed7e5c4a176']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.4b366da9c4000b12"

   strings:
      $hex_string = { 663902740542424e75f63bf07507b857000780eb0b8b55103bd074042bce890a5e5dc20c00cccccccccc8bff558bec568b750856ff155810000166833e227521 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
