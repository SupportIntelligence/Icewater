
rule k2321_2b14ed699c9b0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2b14ed699c9b0b12"
     cluster="k2321.2b14ed699c9b0b12"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba emotet vbkrypt"
     md5_hashes="['0a7ddf093de4431c88001b3a85af4f9c','43f99db5e90a0ad48560b3f4fdfb5b8f','8468dad828b87cd21832a556fa445e43']"

   strings:
      $hex_string = { be674f4971f1a0e464c43c018bc563f8410290c080ce0aa150cce54af97c70259ad4373d87a6a48c1e3972dcd8317f8e879faf0f9bc9848320530de89198337e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
