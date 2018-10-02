
rule n2319_11341c70c956e936
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.11341c70c956e936"
     cluster="n2319.11341c70c956e936"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script fakejquery html"
     md5_hashes="['6d196dd4c0900b6264d9a8db01c230d2969ed0d1','9f9c5d93f7acfb7aba90c339caffb97b1086d09c','5b5e7faa1a4123a7bb7e666b7d1c6a420eeafc4c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.11341c70c956e936"

   strings:
      $hex_string = { 5b5d2c2131292e6c656e6774687d7d293b76617220782c793d612e646f63756d656e742c7a3d2f5e283f3a5c732a283c5b5c775c575d2b3e295b5e3e5d2a7c23 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
