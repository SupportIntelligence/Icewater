
rule k2318_4d3db92b939b0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.4d3db92b939b0932"
     cluster="k2318.4d3db92b939b0932"
     cluster_size="1208"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redirector"
     md5_hashes="['a6a8022be6b441c81b4c5cb7b57c3318b55dd9fc','0e262bf2718a843d8763c94b5f603dc95f107413','cc490d58792c7c7c3687975b76ff85fa9f4d9a3a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.4d3db92b939b0932"

   strings:
      $hex_string = { e8ece5f02030352f32312f313937302922293b0a0a2020636865636b5f696e7075742822656d61696c5f61646472657373222c20362c2022cfeeebe520452d4d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
