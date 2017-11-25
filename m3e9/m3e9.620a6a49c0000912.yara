
rule m3e9_620a6a49c0000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.620a6a49c0000912"
     cluster="m3e9.620a6a49c0000912"
     cluster_size="1521"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="soft zulu downware"
     md5_hashes="['004286058bbea389622be0a0d0414fff','005f7c33e0506ca15c86bf822275ae11','01ed5c548974b1c19c3d52da84f03b21']"

   strings:
      $hex_string = { c5d068eba89c99058a5e9917911c89bbbd92bc86886b6350583fcd9aa4ece810677dab6d5783d1017039753c93b65a8236592e54fea1ccd437b3b16f3b61f0b8 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
