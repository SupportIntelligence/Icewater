
rule m3f7_49102244dabb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.49102244dabb0912"
     cluster="m3f7.49102244dabb0912"
     cluster_size="3"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker script autolike"
     md5_hashes="['205a83b9c18d234c4be248cb9bd34cfb','9c697eb439ce65b9e93675b492d0520e','f3945c81b0c4888e5f374a1c002e9ffb']"

   strings:
      $hex_string = { 32385c783236636f6c6f72735c78336443677430636d467563334268636d56756442494c64484a68626e4e7759584a6c626e516142794d794e54517a4e475569 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
