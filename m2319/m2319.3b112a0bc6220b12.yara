
rule m2319_3b112a0bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.3b112a0bc6220b12"
     cluster="m2319.3b112a0bc6220b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script classic"
     md5_hashes="['225967644f090f3a7625ad1d4a29fdfd7db414a2','e22fe854e1f698b7658b07009b2e1ce4d069b647','9ae76cec35af9b94cd6d36d84c334d0775b2c842']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.3b112a0bc6220b12"

   strings:
      $hex_string = { 3a766f696420307d2c673d303b6e756c6c213d28683d6b5b675d293b672b2b29612e6e6f64654e616d6528682c2273637269707422292626692868297c7c2865 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
