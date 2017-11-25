
rule k3f7_1315c87acb830912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.1315c87acb830912"
     cluster="k3f7.1315c87acb830912"
     cluster_size="5"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hidelink html script"
     md5_hashes="['0215a98e24e199481e00711be98e60b5','13e8d016e321d7adf69d67922242f32e','967f74e85bead980e0ca7ec2020b6106']"

   strings:
      $hex_string = { 7a6c652e636f6d2f6475636b73686f772a3f74633d32333835353732333639353834353132373022207461726765743d225f626c616e6b223e3c696d67207372 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
