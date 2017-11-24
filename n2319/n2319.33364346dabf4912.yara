
rule n2319_33364346dabf4912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.33364346dabf4912"
     cluster="n2319.33364346dabf4912"
     cluster_size="5"
     filetype = "ASCII text"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack clicker clickjack"
     md5_hashes="['13c55962cdf7afc9f4bfe992cd4f61d3','2aea4b18e3c7c5bb588f39bb996b4be6','735e8d187229b5ebcabaa80e5e29565b']"

   strings:
      $hex_string = { 426c6f6753656172636856696577222c6e6a293b766172206f6a3d2f5e5b2b612d7a412d5a302d395f2e2123242526272a5c2f3d3f5e607b7c7d7e2d5d2b4028 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
