
rule m2377_50993949c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.50993949c4000b32"
     cluster="m2377.50993949c4000b32"
     cluster_size="16"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['03f081ee4ed3df2ed428ba43b23b070d','27421777ab5bf3413b8e0e8e0024e37f','f99a317d0cdcac97660ee07753fa6923']"

   strings:
      $hex_string = { c700d40a0d5350cc0f2acfddac8cdae36b1b15bf783b9adea549c43c9543235a8ee0b04d402b86476668870b5222fe4ff22b675df063621317a404d770642ec9 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
