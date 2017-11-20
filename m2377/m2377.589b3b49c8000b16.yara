
rule m2377_589b3b49c8000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.589b3b49c8000b16"
     cluster="m2377.589b3b49c8000b16"
     cluster_size="5"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['073edc3c66495ea0ed87fdca6563f3e9','1e79802498609d3510cfaa2475bdf812','cb432039860c4d85881d6d9b91529404']"

   strings:
      $hex_string = { 07768dec616c26a701985313fbe9c713daca18d6a6ed9e9dba8002e67220a95a3e7ca80a8479e204560fd9838e8ce015df174bb72e2806681a2d00cd741f5541 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
