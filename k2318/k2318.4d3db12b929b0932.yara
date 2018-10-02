
rule k2318_4d3db12b929b0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.4d3db12b929b0932"
     cluster="k2318.4d3db12b929b0932"
     cluster_size="73"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['ca6786fd84b48e02bbc3d3c3e0d6416205108d4f','c229317db0c980337be4ca57875e553ee3fe343b','f47d2edd133f4b6881b9f9da93b6740a5c8e4e59']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.4d3db12b929b0932"

   strings:
      $hex_string = { e8ece5f02030352f32312f313937302922293b0a0a2020636865636b5f696e7075742822656d61696c5f61646472657373222c20362c2022cfeeebe520452d4d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
