
rule k2318_4cbdb12b929b0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.4cbdb12b929b0932"
     cluster="k2318.4cbdb12b929b0932"
     cluster_size="99"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redirector"
     md5_hashes="['4c7049425692e003c0f445ea7f9d2ceecae75017','65819ea66ff044410fad32d78afd4b6afdd70890','a4d8a21f41073c63b24659ef9314463d6018de63']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.4cbdb12b929b0932"

   strings:
      $hex_string = { e8ece5f02030352f32312f313937302922293b0a0a2020636865636b5f696e7075742822656d61696c5f61646472657373222c20362c2022cfeeebe520452d4d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
