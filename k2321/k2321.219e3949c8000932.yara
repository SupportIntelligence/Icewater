
rule k2321_219e3949c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.219e3949c8000932"
     cluster="k2321.219e3949c8000932"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nitol fdld ddos"
     md5_hashes="['09c4fc224b4ae864688f803263260b22','66d2a5a5475e94b04a2472bec8cfc69f','d3c0991a823224675f54c5ca72bd2437']"

   strings:
      $hex_string = { fd3c669f6293d388832a3ba6b22d793ab942afe7a6ee7aa1c81967b3e1aa940a105d16aff84bfb03a509bb11296a1233865e7d98ae40e3246d5a2fa28e222614 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
