
rule o26d4_331b11e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26d4.331b11e9c8800b12"
     cluster="o26d4.331b11e9c8800b12"
     cluster_size="17"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious neoreklami"
     md5_hashes="['7c2d214ad75bd1c1e3e528b8046b109320dc6ae1','baa0f5302bed2a3e1c45e6244e624f79aa2c53aa','6bbcff277c967641db4d1cec61697fc548cb6128']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26d4.331b11e9c8800b12"

   strings:
      $hex_string = { 0000dc4400105a040000ec44001065040000fc4400106b0400000c4500106c0400001c4500108104000028450010010800003445001004080000bc1f00100708 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
