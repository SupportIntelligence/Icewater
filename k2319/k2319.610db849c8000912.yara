
rule k2319_610db849c8000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.610db849c8000912"
     cluster="k2319.610db849c8000912"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="multiplug script asmalwsc"
     md5_hashes="['a9a0b5b8ead15c344d3e53d7d4ae9da26a6ba4b7','6cd84695e3ada9e96c475122aec85d2c426210fc','b4e9fd06049bf2b15569c5ce457d76a70482c4fc']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.610db849c8000912"

   strings:
      $hex_string = { 297b72657475726e2059213d523b7d7d3b2866756e6374696f6e28297b7661722059303d226f77222c6f353d22656e65222c54303d224c69222c7a303d226445 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
