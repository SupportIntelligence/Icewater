
rule n3f8_492c1346ce210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.492c1346ce210912"
     cluster="n3f8.492c1346ce210912"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="droidkungfu androidos kungfu"
     md5_hashes="['da6eb0d57cf67af7019d8fd2157ff280618a5c45','069f9a5c25e7a9e3eb2352c6a7182ef5afdc7017','9f946a142c742269753f4cf8cf429ce96b80f764']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.492c1346ce210912"

   strings:
      $hex_string = { 706c617941644e6f7469666965723b00184c636f6d2f776170732f4f6666657273576562566965773b00134c636f6d2f776170732f53444b5574696c733b001f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
