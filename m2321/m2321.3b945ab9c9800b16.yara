
rule m2321_3b945ab9c9800b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.3b945ab9c9800b16"
     cluster="m2321.3b945ab9c9800b16"
     cluster_size="8"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma tinba"
     md5_hashes="['1509ae19a8e008491d65b96cf53df862','1db5eb02440dc1303e3f9a5c8e1889f7','fe2115c97f0334dc7f0137d8f17fa499']"

   strings:
      $hex_string = { debd3ebcf87c12ffcc869b91fe1eb4d13c8197ef66edbe4ffb0cc5eae793c4eb99549264a970f167c75ca1fc2e6d79576df975cf2789d74bd9f2f45a3f2d7faa }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
