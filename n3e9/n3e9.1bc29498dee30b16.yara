
rule n3e9_1bc29498dee30b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1bc29498dee30b16"
     cluster="n3e9.1bc29498dee30b16"
     cluster_size="8"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply malicious bocdu"
     md5_hashes="['5ade243c73670726594d7e974d72ccff','646a80226843e53db828f13b9f97bfb4','d48b3d943752f46dda64a722c8b8c0d5']"

   strings:
      $hex_string = { 00720063006800050041007000720069006c0003004d006100790004004a0075006e00650004004a0075006c0079000600410075006700750073007400090053 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
