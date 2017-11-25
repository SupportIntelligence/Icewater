
rule m3e9_751c94e1c6000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.751c94e1c6000b32"
     cluster="m3e9.751c94e1c6000b32"
     cluster_size="49"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob malicious"
     md5_hashes="['00e66ab7fa681eaf5ef525177b74759b','0161032c8dcc2cb80b7307cf1e897996','36542e7309c082faf6f2d7ebf9bd282e']"

   strings:
      $hex_string = { 760b880e464f408a0884c975e185ff7403c606005f5e8a0880f920740580f909750340ebf15dc20c00cccccccccc8bff558bec83ec44a13c200101578b7d086a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
