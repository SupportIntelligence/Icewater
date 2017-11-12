
rule n3ed_0c89a5a692d31912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.0c89a5a692d31912"
     cluster="n3ed.0c89a5a692d31912"
     cluster_size="20"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bmnup"
     md5_hashes="['079762ae01bcf3a4986b433270350680','0b79e540c82fea6ac85a528d76d23a7e','ea8baff2ed305805a5f455d6b538366c']"

   strings:
      $hex_string = { 7377745f696e7465726e616c5f77696e33325f4f535f4e4d52454241524348494c4453495a455f3173697a656f664038005f4a6176615f6f72675f65636c6970 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
