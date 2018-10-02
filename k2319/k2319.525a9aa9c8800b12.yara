
rule k2319_525a9aa9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.525a9aa9c8800b12"
     cluster="k2319.525a9aa9c8800b12"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['bae8f5d9ca24b7139754a7f78f07a1100a7b12b5','e3c1b4a0706c7004e22c6bba78d485ad93b51fda','5e9cb9ca06fbfddba4b002a49ed71c9d77745d9b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.525a9aa9c8800b12"

   strings:
      $hex_string = { 646f773b666f72287661722058304e20696e20533075304e297b69662858304e2e6c656e6774683d3d3d282830783133342c32382e364531293e30783143343f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
