
rule j26bf_18d66c9cc2210b30
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26bf.18d66c9cc2210b30"
     cluster="j26bf.18d66c9cc2210b30"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="ursu dotdo malicious"
     md5_hashes="['b46f087158606bc98f1a7ca0bbbbabc17c8bc5b9','6f2979e81d5c9cbd318f589db25941f7ef61bda2','0c1f53d82be27cb8f9bff542b7b3b1bddd93e6c1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26bf.18d66c9cc2210b30"

   strings:
      $hex_string = { 7946696c6556657273696f6e417474726962757465004e65757472616c5265736f75726365734c616e67756167654174747269627574650053797374656d2e44 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
