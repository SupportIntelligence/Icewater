
rule k2318_4cbdb92b929b0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.4cbdb92b929b0932"
     cluster="k2318.4cbdb92b929b0932"
     cluster_size="23"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['93d45c8ef00ddbd9d0e8d6525ff080250d0c0553','b25db5805481a2259ce25f1a1a8b0400e5279309','c47a792858226ddb9dae487a592e4caed0797c2e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.4cbdb92b929b0932"

   strings:
      $hex_string = { e8ece5f02030352f32312f313937302922293b0a0a2020636865636b5f696e7075742822656d61696c5f61646472657373222c20362c2022cfeeebe520452d4d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
