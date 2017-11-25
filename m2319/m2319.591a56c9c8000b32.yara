
rule m2319_591a56c9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.591a56c9c8000b32"
     cluster="m2319.591a56c9c8000b32"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker script"
     md5_hashes="['36059f7dfb774654d336fa63f2b3936b','3f52ec42cfbab98d38300aada550e4d4','dba3e32f94496e5b1c26611d28661dd0']"

   strings:
      $hex_string = { 6a756963796164732e636f6d2f616473686f772e7068703f61647a6f6e653d3137343435383e3c2f696672616d653e0a3c212d2d4a7569637941647320454e44 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
