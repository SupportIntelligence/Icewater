
rule m3f7_63b10284da630912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.63b10284da630912"
     cluster="m3f7.63b10284da630912"
     cluster_size="11025"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['00055cab6774daec000b267dabcf3ad7','000571eef1ba568d17d79d4016eaf208','0058343ac25ad3c5ea329c26bbf61858']"

   strings:
      $hex_string = { 6369616c466f6c646572283229202620225c2220262044726f7046696c654e616d650d0a49662046534f2e46696c654578697374732844726f7050617468293d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
