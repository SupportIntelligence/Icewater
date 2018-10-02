
rule m3f8_6d16ea48c0000b30
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f8.6d16ea48c0000b30"
     cluster="m3f8.6d16ea48c0000b30"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos fakeinst smsagent"
     md5_hashes="['0dfcd7846f78883439f24852f6fc9b46519dd600','a913a946e1566008a54c2f2428db1ba961a56dfa','365ffe00bfc48abaf7a1fd7143e68bfd82c865c0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m3f8.6d16ea48c0000b30"

   strings:
      $hex_string = { 575f4f5554474f494e475f43414c4c0021616e64726f69642e696e74656e742e65787472612e50484f4e455f4e554d424552000770686f6e653a20000a697352 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
