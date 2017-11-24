
rule k3e9_1b1c6898b1a10b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1b1c6898b1a10b16"
     cluster="k3e9.1b1c6898b1a10b16"
     cluster_size="522"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="neshta hllp neshuta"
     md5_hashes="['0097de110a5fa104749044d38cd8e8c0','009c656b32664d060ff803265833442b','0c09e8641af194759c664e45302049be']"

   strings:
      $hex_string = { 4b5d172fd4e4d188e271cbb6cf117138d57af4f1ce82113430a737b3df0fe27de88b371a188c1b63121470bc6e0b2bb8db8f556167254e9663c7c94f8b6268ad }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
