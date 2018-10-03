
rule m26c0_1423c117872af111
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26c0.1423c117872af111"
     cluster="m26c0.1423c117872af111"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="symmi virut malicious"
     md5_hashes="['3b23a1cfe12029f6b5f621f11e4630f8203b325a','22a9d883ece5bee192185b27cdfc138d73801f9f','1d03c5861e818aceba5501bc46db200421a0e367']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26c0.1423c117872af111"

   strings:
      $hex_string = { 87a5f5316c6d038cdcda08a32f37c158e5669870b939269d6b85c9cc814fdbd60e3f6eeb80999b3a61367be8e7afef8a251bba63150162d7eede387eb01fae9e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
