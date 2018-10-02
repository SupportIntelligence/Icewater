
rule m2726_44d2b0941302c4f6
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2726.44d2b0941302c4f6"
     cluster="m2726.44d2b0941302c4f6"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="symmi malicious stantinko"
     md5_hashes="['b4180e18cfd6b44dd0a2d1817aaf7ebfa94528bc','fe642c3c58bc94b64eecc48624bfd4a8391c809e','0ef497c3f2ed8f0007534a98e4593e6f00b9befc']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2726.44d2b0941302c4f6"

   strings:
      $hex_string = { 0f72118d50f1b881808080f7e2c1ea078d4cd108894d0883c7253b7df80f8601ffffff8b45085f5e5b8be55dc30facd11868b179379ec1ea186887caeb85e946 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
