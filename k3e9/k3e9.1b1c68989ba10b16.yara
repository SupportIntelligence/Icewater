
rule k3e9_1b1c68989ba10b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1b1c68989ba10b16"
     cluster="k3e9.1b1c68989ba10b16"
     cluster_size="9"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="neshta hllp malicious"
     md5_hashes="['02e950c07bd3ca4f44b86907ff69ee17','1dc9eb68d2e5c6c1bac5ef748dded959','fbd11880ff7a24c9e5a09f9cf04ea84c']"

   strings:
      $hex_string = { 431852503b50207e05e873e6ffff585987481c8b50188d148a595fb80d00000038277414893a83c204f2ae750b8867ff803f0a75eb47e2e85f5bc38bc0575152 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
