
rule n3f8_43d16a08c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.43d16a08c0000b12"
     cluster="n3f8.43d16a08c0000b12"
     cluster_size="210"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="zdtad androidos inoco"
     md5_hashes="['aa178ce6bb6db6e895a2e990e4dceac602111498','a44a190519c045980c9c240e0b63038781d57a36','5e3b78b28b30e1887b769c6d0f6dec890fffd1bb']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.43d16a08c0000b12"

   strings:
      $hex_string = { 7368696e67e78ab6e6808129001e737461727441643128e5889de5a78be58c96e99499e8afaf20e4bca0e585a5e79a84636f6e746578e4b8ba6e756c6c290025 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
