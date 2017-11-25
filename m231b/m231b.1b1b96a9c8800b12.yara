
rule m231b_1b1b96a9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m231b.1b1b96a9c8800b12"
     cluster="m231b.1b1b96a9c8800b12"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker script autolike"
     md5_hashes="['0b6dd38b5e928d64cd0e7a6b5f6884ff','0e7a08328f1dfa483e456104db738064','ac115699831659a25d06f708e87d00de']"

   strings:
      $hex_string = { 41414361592f57374d4635714b4f3273452f7334372f30362e676966272f3e22293b0a74686554657874203d20746865546578742e7265706c616365282f3a5c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
