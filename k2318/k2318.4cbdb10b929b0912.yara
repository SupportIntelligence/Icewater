
rule k2318_4cbdb10b929b0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.4cbdb10b929b0912"
     cluster="k2318.4cbdb10b929b0912"
     cluster_size="17"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redirector"
     md5_hashes="['07c7e3897aa0c2b6ec9d4b5b4957a49fbb7a648f','359e86f9dc2d9f55f32196143eeb82a8a013098a','819cf42ff8df87c05c197fde91d85776560b70d6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.4cbdb10b929b0912"

   strings:
      $hex_string = { e8ece5f02030352f32312f313937302922293b0a0a2020636865636b5f696e7075742822656d61696c5f61646472657373222c20362c2022cfeeebe520452d4d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
