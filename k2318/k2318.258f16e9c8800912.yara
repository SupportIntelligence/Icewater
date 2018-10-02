
rule k2318_258f16e9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.258f16e9c8800912"
     cluster="k2318.258f16e9c8800912"
     cluster_size="341"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redirector"
     md5_hashes="['3fa332b0ec8ccb738bcf6ed12e6b2491caaa0840','156bc045b8d721bd8b41d7c4092f4d29ac03200b','c0a2fff00e474f0d1851e134358c94f37fe62470']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.258f16e9c8800912"

   strings:
      $hex_string = { 72792f696e6465782e7068703f63506174683d3333223ee3eeece5eeefe0f2e8f7e5f1eae8e520eff0e5efe0f0e0f2fb3c2f613e266e6273703b283131293c62 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
