
rule k26bb_193e69e159b2e316
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.193e69e159b2e316"
     cluster="k26bb.193e69e159b2e316"
     cluster_size="18"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="installcore unwanted dealply"
     md5_hashes="['4f3ac0785a35924b4860b93e10aeba4dd5241b4a','f3e6e0a27752cb732af116f1cc5288becb76bfa9','f94a589f5f21a4994be53eba6a29e7d66f2caaf2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.193e69e159b2e316"

   strings:
      $hex_string = { 1654436f6d70726573736564426c6f636b526561646572905633f6b95cc540008bc6ba08000000a8017409d1e8352083b8edeb02d1e84a75ee89014683c10481 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
