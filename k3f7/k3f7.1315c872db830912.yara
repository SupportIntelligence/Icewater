
rule k3f7_1315c872db830912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.1315c872db830912"
     cluster="k3f7.1315c872db830912"
     cluster_size="5"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hidelink script html"
     md5_hashes="['1a3b1e3df33b6431df3e307a99527ecb','2642d9bf1cb607262070628756a77d15','8c437d4b9f8a392693d01835a9d1fb14']"

   strings:
      $hex_string = { 7a7a6c652e636f6d2f6475636b73686f772a3f74633d32333835353732333639353834353132373022207461726765743d225f626c616e6b223e3c696d672073 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
