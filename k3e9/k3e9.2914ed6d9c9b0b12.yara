
rule k3e9_2914ed6d9c9b0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2914ed6d9c9b0b12"
     cluster="k3e9.2914ed6d9c9b0b12"
     cluster_size="7"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy emotet"
     md5_hashes="['782be4cb93edce2ad1c0fb546fade802','94c1a24b94f3bb08753834242a63bf0d','fdc161ade89f10a1477bf32d2fbf0151']"

   strings:
      $hex_string = { be674f4971f1a0e464c43c018bc563f8410290c080ce0aa150cce54af97c70259ad4373d87a6a48c1e3972dcd8317f8e879faf0f9bc9848320530de89198337e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
