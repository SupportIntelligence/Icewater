
rule m3e9_16db1428de8bdb16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.16db1428de8bdb16"
     cluster="m3e9.16db1428de8bdb16"
     cluster_size="140"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cerber ransom zbot"
     md5_hashes="['018cdec2959dea6af19f85059a6b0820','08c0cac22646e26d273048608dd6f1e0','550e37a3c83b859e935ebf1e66221d6b']"

   strings:
      $hex_string = { 89fdcb62aea2293f032f1e45ae929971bbfd2b3faea2294553b9ffc8c1929971c0870070ae62f8c74dba80d03f615970ae87e06fae51d58d4d54e3d088f6de6f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
