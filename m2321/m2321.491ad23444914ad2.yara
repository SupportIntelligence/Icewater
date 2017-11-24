
rule m2321_491ad23444914ad2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.491ad23444914ad2"
     cluster="m2321.491ad23444914ad2"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre allaple hoax"
     md5_hashes="['246f4bb6d88ae1b16db01e0d5514007f','3cca2d4a2ad383271b03135eb7db3e65','8fa3b9d4f7ddff385db607e7dd6f6a2b']"

   strings:
      $hex_string = { f0310030c1857e34d76cc67b28d2b0cff3659d32fde16d4caebff29405fa119f8edf40fbd9f40b22f616ad3d77a23541e658fe277438eb4698a6b304e3dd8443 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
