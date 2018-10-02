
rule pfc8_1b9b9be9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=pfc8.1b9b9be9c4000b12"
     cluster="pfc8.1b9b9be9c4000b12"
     cluster_size="181"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="aiodownloader androidos andrsca"
     md5_hashes="['5ee0e4ac51caae67dd8bf4a5de2bc012b89048ee','dc7fc0799aef0f223211490a46a53d7ffd8f80dd','0f42ec6347b51e8e2089f2897b3de8ce9b53045c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=pfc8.1b9b9be9c4000b12"

   strings:
      $hex_string = { 4374524e536600b24f1b412efdbc6a9cf8d78378fa09e5c8b8b5afa9a47c0af4f2d394918a6d605f5a48eedcac8f7f7572c48e7bfcebdfd0a087f1ece1dad5c1 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
