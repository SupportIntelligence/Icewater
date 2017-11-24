
rule n2321_0b9d6a48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.0b9d6a48c0000b12"
     cluster="n2321.0b9d6a48c0000b12"
     cluster_size="48"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="renamer cgmu delf"
     md5_hashes="['08604909061b4e169ce17feaab61a27f','0f89e5e9dcc4c72a9b55afce293dc699','75be950710406423b048814f17fbe1b8']"

   strings:
      $hex_string = { d7b89c6bb67996bf725d8d5c56ed2cf91318da9a7e01680bd23a7beb2744e389d9061655dd2fc18ccfc987603b0443a230fe22649fa673e20a2de12bb4089975 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
