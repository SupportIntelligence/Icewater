
rule o2319_699d3949c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o2319.699d3949c8000932"
     cluster="o2319.699d3949c8000932"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="cryxos coinminer coinhive"
     md5_hashes="['ce38728ffa4b7f98646224224b7937ff1e8205e6','a0289858fb1cf73000e65a51ff7da64d2ced6031','2c041f6fc147f8e7d85882e15bbc9557e2e8305c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o2319.699d3949c8000932"

   strings:
      $hex_string = { 3d7c765c2f293f285b412d5a612d7a302d392e5f252d5d2a29285c265c532b293f2f293b0a0a0909096966202869645b335d2e696e6465784f662827796f7574 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
