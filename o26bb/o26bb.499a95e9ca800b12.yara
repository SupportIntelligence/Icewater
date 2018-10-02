
rule o26bb_499a95e9ca800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.499a95e9ca800b12"
     cluster="o26bb.499a95e9ca800b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious based beeaf"
     md5_hashes="['0c8cd34ab3818c02ce4c3a61f65eb36689e16f7f','4dca109896df6def45dd8456042cb49a74439713','1a52e6dd09de86d0e17c0aeb43f51af9589dd48e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.499a95e9ca800b12"

   strings:
      $hex_string = { cf64cb68a72e70e774e478a08e8afc92c4043de5bc542d01106a0f304b1b0bb43a24ec60f856a378f37cf28076281f88841c3149f05a023933b62c04b89dba1d }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
