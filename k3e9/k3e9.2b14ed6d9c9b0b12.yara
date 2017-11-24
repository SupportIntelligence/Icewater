
rule k3e9_2b14ed6d9c9b0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2b14ed6d9c9b0b12"
     cluster="k3e9.2b14ed6d9c9b0b12"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba emotet zusy"
     md5_hashes="['45f28c2ac7300e2b502f14ce4e0c8e8a','4c41324dfa62be1585ff19bc8ffa928c','b44f9bb4211681c911d4e27571021bea']"

   strings:
      $hex_string = { be674f4971f1a0e464c43c018bc563f8410290c080ce0aa150cce54af97c70259ad4373d87a6a48c1e3972dcd8317f8e879faf0f9bc9848320530de89198337e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
