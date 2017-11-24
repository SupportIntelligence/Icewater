
rule pfc8_291d9499c2200b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=pfc8.291d9499c2200b16"
     cluster="pfc8.291d9499c2200b16"
     cluster_size="58"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="androidos triada ransomkd"
     md5_hashes="['036c38006a53ecf33ab6fde65041e760','047767cc74cfa256b4e5db720549839a','637ce840e85b10ab58efa80269cf89fd']"

   strings:
      $hex_string = { 1099c1b5a450b8516e38be84effb835dd1f94f753fcca3707f087b19ec984e904b96b0f793af9730d985dc591b2deac52431430e76925bb20bf236a677ab237e }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
