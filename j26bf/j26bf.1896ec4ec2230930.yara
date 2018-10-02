
rule j26bf_1896ec4ec2230930
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26bf.1896ec4ec2230930"
     cluster="j26bf.1896ec4ec2230930"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dotdo malicious heuristic"
     md5_hashes="['aae5c44c44871961895cfc9a51f8a114ef2c3b15','74ee812bc004ac0193068ce673663e8ce00c199e','6ba5e7cbb3a419fe13814289c5dcc3a01e06395b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26bf.1896ec4ec2230930"

   strings:
      $hex_string = { 756c740044656661756c740073656e646572006500646973706f73696e670076616c75650053797374656d2e5265666c656374696f6e00417373656d626c7954 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
