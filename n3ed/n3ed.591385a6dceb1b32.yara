
rule n3ed_591385a6dceb1b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.591385a6dceb1b32"
     cluster="n3ed.591385a6dceb1b32"
     cluster_size="38"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bqjjnb"
     md5_hashes="['14f9716b6d31442ff236ac4df4509c6f','191cfe64dbd2990c4e60dea306a6ab61','ac30fede189d9d774b5b350312722d34']"

   strings:
      $hex_string = { 4d083bcb7c062bcbd3e8eb288a1688550b4633d22bd98a4d0b570fb6f9c1ef0703c00bc702c942f6c20774048a0e46424b75e75f5e5b5dc3568bf18b461085c0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
