
rule m2321_4991d1a996bb0b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.4991d1a996bb0b32"
     cluster="m2321.4991d1a996bb0b32"
     cluster_size="20"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="oxypumper adload bdxe"
     md5_hashes="['1af7bf4ff7acc8459b5e72afeedeb54c','20711d8999cf3ca766530305a6839ea0','d669d00818ac9e80a3a19451261385d8']"

   strings:
      $hex_string = { 534bb042fa679661f7b72c0e547be8e2c9559968884c79f415d411491b1f5f738eafa49baa3dec05c1279f9530d37833744fcbd1a72b066fc12f5752448dbbf3 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
