
rule m2321_412c4a14a8696b96
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.412c4a14a8696b96"
     cluster="m2321.412c4a14a8696b96"
     cluster_size="30"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nsis adload clickdownload"
     md5_hashes="['00a6b84cad5b0969595d68b82740f76d','0973b9ae6539c6165447170ab3eec642','9356241cfc7515acdf3e210b00e230f8']"

   strings:
      $hex_string = { e524d60d1d03adbb54e3dcdf4cd9b160c9cddeb018dbd592115f752e167331f3f48293780be420708a63fbd3c33ac27cee640c9998aabc0a6fc633f761894dea }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
