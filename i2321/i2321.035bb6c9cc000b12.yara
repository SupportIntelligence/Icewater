
rule i2321_035bb6c9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2321.035bb6c9cc000b12"
     cluster="i2321.035bb6c9cc000b12"
     cluster_size="10"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cosmicduke backdoor razy"
     md5_hashes="['16b86734180ee5022ba13af7c2d04fa6','29d8d7ecd2cb898ccef770928f86825b','e83eac6e2bdce4e541bf1a267a624812']"

   strings:
      $hex_string = { b796df6fee683d165bf514a7da8db2ca0f9ddea8ddbbf2d4e9cbb9d849bcbdb661e9bdeae45429b6da51ac3e1ebf746743f55aecae1aeb5d4afa42cc2eaf2d8e }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
