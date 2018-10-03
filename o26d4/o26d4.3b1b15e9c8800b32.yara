
rule o26d4_3b1b15e9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26d4.3b1b15e9c8800b32"
     cluster="o26d4.3b1b15e9c8800b32"
     cluster_size="31"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious neoreklami"
     md5_hashes="['3293a8a1959f0345655a3ac48b718ca8e27cce53','106e4079d92c2112954a7e59fce8937e5719ca21','88a313f20c40b0c0927b8238da6fe6d8e79b16b4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26d4.3b1b15e9c8800b32"

   strings:
      $hex_string = { 0000dc4400105a040000ec44001065040000fc4400106b0400000c4500106c0400001c4500108104000028450010010800003445001004080000bc1f00100708 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
