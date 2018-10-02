
rule n26bb_4a5c71ae93e39b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.4a5c71ae93e39b12"
     cluster="n26bb.4a5c71ae93e39b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="symmi riskware attribute"
     md5_hashes="['48a289f90cc59c74c1a221d2bbf7ea86fe254017','3cee2aa191aa4cfdb624fbb26435472725c3b5ce','47e8d1323773015e0aba7a41007598e2c0f86068']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.4a5c71ae93e39b12"

   strings:
      $hex_string = { 52c74424622e3f7b00e8b90affff8bf885ff74100f1f008a073c2074043c09751447ebf38bce8d51018a014184c075f92bca8d3c316a0368b0584a0056e8a8fc }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
