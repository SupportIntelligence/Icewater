
rule k26bb_528aec69c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.528aec69c8000b32"
     cluster="k26bb.528aec69c8000b32"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="virtob malicious virut"
     md5_hashes="['bb034fa5a1b81bf663137ff5565e50cbb6428869','75e9a567759e8457cae48ce6d4fc1ab79006eb00','de62e526d29437f44e59851a9525b51ccd00b686']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.528aec69c8000b32"

   strings:
      $hex_string = { 0001f7d68935886000015e5f5bc9c3be4fe640bbebe690909090908bff558bec568b750833c03b750c731185c0750d8b0e85c97402ffd183c604ebea5e5dc3b8 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
