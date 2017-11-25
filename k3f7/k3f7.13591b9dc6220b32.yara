
rule k3f7_13591b9dc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.13591b9dc6220b32"
     cluster="k3f7.13591b9dc6220b32"
     cluster_size="6"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hidelink html script"
     md5_hashes="['0f5f441b395c95087b259ecf30494908','117a46cf932acc46fc00225778a1bda3','da73be2bb459738c5efbd16bfe260f86']"

   strings:
      $hex_string = { 3a2f2f6a6f7a79616c7469646f72652e636f6d2f6e6577735f6d656469612f6576656e74732d63616c656e6461722f223e4556454e54532043414c454e444152 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
