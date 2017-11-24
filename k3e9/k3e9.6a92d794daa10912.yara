
rule k3e9_6a92d794daa10912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6a92d794daa10912"
     cluster="k3e9.6a92d794daa10912"
     cluster_size="459"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nsis adload trojandownloader"
     md5_hashes="['0035c4fbcafee98d0396160c6054f643','00477be655e9ed44c9058f4e360caf87','073346efffadd042f09a2dd6290e70f4']"

   strings:
      $hex_string = { c07c2b568d7041c1e6055703f18d78018b0685c07410837efcff750a50ff150430001083260083ee204f75e45f5ec3518b4424085355568b981408000057895c }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
