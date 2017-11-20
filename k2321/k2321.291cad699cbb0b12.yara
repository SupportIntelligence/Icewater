
rule k2321_291cad699cbb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.291cad699cbb0b12"
     cluster="k2321.291cad699cbb0b12"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171117"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy emotet"
     md5_hashes="['293cee4b5ef35949b85c2dab25e381ee','4b9c578053125ecfa10b9859b0466200','e5e282946f3c356f8bcc67a29d5bb95c']"

   strings:
      $hex_string = { 496b664aaa67882b734595d3847533f8f5b9dcb353d85f0ff7ddd687312d560cd3b4fe3aa9540263f9dc76f0107059423e572a93eafcfd7b8606cc4890bed49f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
