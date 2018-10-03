
rule i26e2_150b3219c2001122
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i26e2.150b3219c2001122"
     cluster="i26e2.150b3219c2001122"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dorkbot winlnk dobex"
     md5_hashes="['5e0594432432efdac0153d9e3246b7aa121d397d','46453d65227017749702b54749fdac8230bc16c0','1dd50c93f356e8a68cc6908af7da30814a8d919d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=i26e2.150b3219c2001122"

   strings:
      $hex_string = { 1f50e04fd020ea3a6910a2d808002b30309d19002f433a5c00000000000000000000000000000000000000520031000000000000000000100077696e646f7773 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
