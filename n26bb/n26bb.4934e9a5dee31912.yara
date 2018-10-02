
rule n26bb_4934e9a5dee31912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.4934e9a5dee31912"
     cluster="n26bb.4934e9a5dee31912"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy genx trojandownloader"
     md5_hashes="['430423a3390217412ce26f6f782ccfaa851ec131','71bce204c3968c8974bf55f7c54e343d3294a085','7b3f5e9fb403bd75941a699da5010b031854e96a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.4934e9a5dee31912"

   strings:
      $hex_string = { 0d5a6a0a580f44d0e87da6ffff8b4f4885c97405e8bc64ffff8b45e0891833c05f5e5bc9c3558bec83ec1453568bf1578975f03b562c762568d47c480068b1f5 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
