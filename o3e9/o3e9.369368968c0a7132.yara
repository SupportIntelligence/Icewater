
rule o3e9_369368968c0a7132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.369368968c0a7132"
     cluster="o3e9.369368968c0a7132"
     cluster_size="1279"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonster installmonstr malicious"
     md5_hashes="['0001b6deed37c21a8bb83df117d832d9','003b12ea862a273afa22dcb9a00d375d','02e9cb72741d478f4c0e67bcca5e0a12']"

   strings:
      $hex_string = { 90f47aad51c4498d6b86fccbec700784e53e0659f6b40dbe907690a8eebf6de512506599dbb29b9c0822cc973e9f86458c2c7100bda182d3183619940d328527 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
