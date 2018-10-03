
rule m2319_599d388bc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.599d388bc6220b32"
     cluster="m2319.599d388bc6220b32"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="hidelink html script"
     md5_hashes="['709abc54957542d1514125cf8aeb4d912a650020','3861d020b436c5341a4c198aa53aac306b1ad18b','1c5b22213c08761f35297ea919d1edbe74627bcd']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.599d388bc6220b32"

   strings:
      $hex_string = { 6c656e6774687d7d293b76617220412c423d2f5e283f3a5c732a283c5b5c775c575d2b3e295b5e3e5d2a7c23285b5c772d5d2a2929242f2c433d6e2e666e2e69 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
