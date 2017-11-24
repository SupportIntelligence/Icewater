
rule m2321_4b5ad23454914af2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.4b5ad23454914af2"
     cluster="m2321.4b5ad23454914af2"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['0562dedb5e6daace6fb9f1bf89c158f2','0b725bc7d7a8b06160ab93853d66c3c4','a7c3bee2e664a69023377edbef6b7f2d']"

   strings:
      $hex_string = { f0310030c1857e34d76cc67b28d2b0cff3659d32fde16d4caebff29405fa119f8edf40fbd9f40b22f616ad3d77a23541e658fe277438eb4698a6b304e3dd8443 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
