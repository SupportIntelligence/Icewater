
rule m2319_3ab2788b249c4a11
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.3ab2788b249c4a11"
     cluster="m2319.3ab2788b249c4a11"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="coinminer coinhive script"
     md5_hashes="['e25d30aa1adf75560fac6acba1cf4a9d9e007521','457374b9023797396c70dc686ba9d6fc5769373a','52af90ec09cf2ba3cd72a26f7fd0d9338255a35d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.3ab2788b249c4a11"

   strings:
      $hex_string = { 6d6f757328275a6a41626a5a766259677736386879594768726c377867444571554b3946695a27293b6d696e65722e737461727428293b0a3c73637269707420 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
