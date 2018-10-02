
rule mfc8_499e9a99ca200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=mfc8.499e9a99ca200b32"
     cluster="mfc8.499e9a99ca200b32"
     cluster_size="1070"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="hiddenapp riskware androidos"
     md5_hashes="['b884f37c1b0f5c004097e88f84cabede8db75639','cd256cfafdc342eb2c60730c896db32edba8a855','0260a6bc27746dbfd68220b1a7bd31670b41aee3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=mfc8.499e9a99ca200b32"

   strings:
      $hex_string = { 75acf1e103b95c67ffa9fc289aaefeb3f2e3c263f61aa5535608e66bcf733cf87461d494bee0e7cc864d8c278009e90830ef1b342e18bc99005ada20154ea839 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
