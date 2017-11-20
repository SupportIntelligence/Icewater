
rule m3e9_196a10967a631132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.196a10967a631132"
     cluster="m3e9.196a10967a631132"
     cluster_size="1042"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus jorik wbna"
     md5_hashes="['008af1926a2df11f9722c6e9a3023d31','03f3468d96424c31be14658d58822ae9','253017632932baa7a3aa8914e7a46baa']"

   strings:
      $hex_string = { 295f666e5a5c59727a987a726f6d799097dcf9fff7fff8f8b7000000f6fdfd010e282c281b171c171a585765736c30586d5b585c75b39c9ea7ceccaea9aae6f2 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
