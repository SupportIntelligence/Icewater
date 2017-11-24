
rule k2321_2b14ad6598bb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2b14ad6598bb0b12"
     cluster="k2321.2b14ad6598bb0b12"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba emotet vbkrypt"
     md5_hashes="['0f34a93241789173e6e4b98f69604dbe','3d0caacec4962ea729742fd9108a4819','f4ef3a13cf526f0b20c21c9a3c497f4b']"

   strings:
      $hex_string = { 30f76eddb879ed6abda9e6f33d7b4a8a8b07a4a622e609582c1e23001280040674560885622e57cae7832bb1a4bee93e382d6de4f0e163468ffa733c02fcfdd8 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
