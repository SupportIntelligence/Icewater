
rule m3e9_5af4eb09c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5af4eb09c0000b12"
     cluster="m3e9.5af4eb09c0000b12"
     cluster_size="136"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nimnul vjadtre wapomi"
     md5_hashes="['01292a51c118c5bba8c17e4c235aab19','02b84950ad4f6fefb578e6871f27c2c0','1b9dca385c89243f813fd7bd0633d622']"

   strings:
      $hex_string = { 1520f49f222c0540a82516ab24be2be1a9a0a6e496b186ba3f9f820a95cb551d5c69871252f3ae6e1301b88c6c71bbcc700a11061943f2ed6a4be65aa417d1c1 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
