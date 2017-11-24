
rule m2319_411a95a1c2000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.411a95a1c2000932"
     cluster="m2319.411a95a1c2000932"
     cluster_size="5"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="script faceliker trojanclicker"
     md5_hashes="['3affdd9f85aeba20c5ba15171134c0f4','4d68c9eed7b2509dd3518d5e27632307','fd127f6feea453e39622a38299e0520a']"

   strings:
      $hex_string = { 3631383836375c783236636f6c6f72735c78336443677430636d467563334268636d56756442494c64484a68626e4e7759584a6c626e516142794d774d444177 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
