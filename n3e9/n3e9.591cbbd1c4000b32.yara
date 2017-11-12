
rule n3e9_591cbbd1c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.591cbbd1c4000b32"
     cluster="n3e9.591cbbd1c4000b32"
     cluster_size="1544"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="elzob graftor shiz"
     md5_hashes="['005daa04ad07c3a08c141e44e778bba1','008b2e5316e480328f773e1295517f41','06f7ae7d565a56e25f8d23b6ee555ad5']"

   strings:
      $hex_string = { 008040c020a060e0109050d030b070f0088848c828a868e8189858d838b878f8048444c424a464e4149454d434b474f40c8c4ccc2cac6cec1c9c5cdc3cbc7cfc }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
