
rule k2321_19183949c4000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.19183949c4000b16"
     cluster="k2321.19183949c4000b16"
     cluster_size="7"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="small generickd upatre"
     md5_hashes="['1474ae97fe51c0a6d0b246cf50def026','419639a9eecec317b59e311627ea4e1a','d67b2567e8421bb7e12a10b0f8a714cf']"

   strings:
      $hex_string = { 067b1657452edf2c2a6d9a95e9bee774d46f02581f83d5fdf0f2a3c127ba798717474eb29ff5cadef5770ad978eacc46dbbc3193946b827f2b9de3325980edf3 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
