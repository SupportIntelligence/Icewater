
rule n3e7_1695cb1fd646caca
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e7.1695cb1fd646caca"
     cluster="n3e7.1695cb1fd646caca"
     cluster_size="10"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ubar downloadmanager helper"
     md5_hashes="['3abb2f917a5b6542480ae1f6d51851cf','4253aab7067222b5484227cc16ff68f7','ef572104b1651c0681971abd2f831cba']"

   strings:
      $hex_string = { 2b8a4a3920a2e2a0a8ac854c8901d48f3dbe5d68536a541be514511c29444131022c87ae7b4dc8d879950b99fa075e743f710067b1e304deb41d6d0aad3ec715 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
