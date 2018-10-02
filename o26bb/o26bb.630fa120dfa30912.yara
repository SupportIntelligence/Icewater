
rule o26bb_630fa120dfa30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.630fa120dfa30912"
     cluster="o26bb.630fa120dfa30912"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bundler malicious softcnapp"
     md5_hashes="['8823371ffca4ae645b2f4de5040178c3eaf3c2d3','6d93762c6b2d502e7a8923f084b1b31d84bb2ccd','1748bc40d9999f4e7176a25c8e6bc85e8837d24c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.630fa120dfa30912"

   strings:
      $hex_string = { 4efd0fb642fd2bc8741233c085c90f9fc08d0c45ffffffffeb0233c985c90f85a1f7ffff668b46fe663b42fe0f8491f7ffffe9450400008b46e13b42e10f8482 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
