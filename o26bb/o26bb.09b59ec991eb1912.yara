
rule o26bb_09b59ec991eb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.09b59ec991eb1912"
     cluster="o26bb.09b59ec991eb1912"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious softcnapp"
     md5_hashes="['a77ef01f4440bee867a80412102755bfc0c0d17e','5c60463015b0d429748c5147f2e8b5bd0d03136c','77be0e383d6518210951369f60b05d1a56b9a960']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.09b59ec991eb1912"

   strings:
      $hex_string = { 0fb6c350e8f513070083c40485c0750a80fb0a740580fb0d75128b4620473b3872da8b068bce6a01ff10eb5f8b4df0eb54b80c955d008bd72bd066908a0884c9 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
