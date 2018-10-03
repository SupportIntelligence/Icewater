
rule k26bb_4324f856cd32e113
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.4324f856cd32e113"
     cluster="k26bb.4324f856cd32e113"
     cluster_size="26"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="virut malicious virtob"
     md5_hashes="['36f7bfe3bf57e98528f2c72462bcf0c5255ca81d','69c6258de5a0c7fbbeb54b16eee1633565affb1d','9b22cb3eb95cd08b20395c76372dfd65a34762fd']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.4324f856cd32e113"

   strings:
      $hex_string = { 663902740542424e75f63bf07507b857000780eb0b8b55103bd074042bce890a5e5dc20c00cccccccccc8bff558bec568b750856ff155410000166833e227521 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
