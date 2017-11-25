
rule m3f7_7913288bc6200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.7913288bc6200b12"
     cluster="m3f7.7913288bc6200b12"
     cluster_size="3"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['413fb2026392097249702d660b362a79','6b3f2c24b46c772bcbff2a26c46ca35b','ebe93f28de04a002ce10e86864a73a97']"

   strings:
      $hex_string = { 31383233374446333432434631354236333741353638414639394230463444454335393142444132383030444632433546364543453933454241354438433430 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
