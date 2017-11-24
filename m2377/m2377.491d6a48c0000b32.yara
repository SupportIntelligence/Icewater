
rule m2377_491d6a48c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.491d6a48c0000b32"
     cluster="m2377.491d6a48c0000b32"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cryxos faceliker script"
     md5_hashes="['421622db8e2b3ceb77b613f3676ff92d','57b173bef5d2e3dfa6db4184d08e4cd9','c7345360120c18323a0030b06fa8c87d']"

   strings:
      $hex_string = { 6b65722e696e666f2f67657470722e7068703f636f6465783d6148523063446f764c324a6c636d7468614449774d544d75596d78765a334e7762335175593239 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
