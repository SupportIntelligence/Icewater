
rule m3e9_611c9cc9cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.611c9cc9cc000b32"
     cluster="m3e9.611c9cc9cc000b32"
     cluster_size="1537"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple rahack backdoor"
     md5_hashes="['00a0a4b6c5b4d172c19e5453769d7b2a','00b208cfcf70b8ec0c4fe759af5dba7d','06d84069f42307ecc2b1355707f2064a']"

   strings:
      $hex_string = { 494f36c822410fbafb33e8acd425c19ead179a90860973825ffb4b7438ed246611dffd58ead1d64ac3c3af3c9cb5882e75a761204e993a12278b1304007decf6 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
