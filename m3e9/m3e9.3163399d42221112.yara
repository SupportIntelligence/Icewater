
rule m3e9_3163399d42221112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3163399d42221112"
     cluster="m3e9.3163399d42221112"
     cluster_size="6"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vjadtre nimnul wapomi"
     md5_hashes="['0f186eb570dd35a432005f63e01ed228','a1bf28c232a024539b9b932c7f950136','e06771353ddd26792682c3e5d33cd36d']"

   strings:
      $hex_string = { 1520f49f222c0540a82516ab24be2be1a9a0a6e496b186ba3f9f820a95cb551d5c69871252f3ae6e1301b88c6c71bbcc700a11061943f2ed6a4be65aa417d1c1 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
