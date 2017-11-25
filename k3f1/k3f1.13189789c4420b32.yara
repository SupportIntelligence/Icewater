
rule k3f1_13189789c4420b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f1.13189789c4420b32"
     cluster="k3f1.13189789c4420b32"
     cluster_size="3"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="mydoom email banker"
     md5_hashes="['2fe5e2120337b72cb2f6a4a69cb1c54f','3d3ffa3510c411d4b06f39aa4d8ddafc','b6c1dfcfaa99619fb945fa877389f7ac']"

   strings:
      $hex_string = { 96f4fd237255876abfe562b2ae07d883fbe4fc2d8b82c852e7a7d65351405fc70f169201043075f8c37961cd026f80be78593bc6595a973ddd6cab13cf488ce3 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
