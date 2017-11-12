
rule m3e9_611c96cfc566f333
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.611c96cfc566f333"
     cluster="m3e9.611c96cfc566f333"
     cluster_size="163"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple virut rahack"
     md5_hashes="['03d564d23d86fd7655d7f55d34173fdc','043517e79268f8943fd60b87b8d2631c','3d900c6207d301d90d8cecf8a2d84d2d']"

   strings:
      $hex_string = { 14bbb73d5da71ccb8d38a33d5adee8cc471a0f6cbc38fd70823b1d94e4d9be94b9ebbe44b4bca74eb6751fd2a5a4abf8c4d7fcfc5c4cc45c2ec1043ca15d1ad9 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
