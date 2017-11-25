
rule m24c4_2b90971adee30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m24c4.2b90971adee30932"
     cluster="m24c4.2b90971adee30932"
     cluster_size="5"
     filetype = "MS-DOS executable (gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="enistery emotet pemalform"
     md5_hashes="['023def5f0e8979d22b56c7db4b0344e0','04888cf500527aae6011ff128c912ce9','cbf1fe9520b9bc44e5feac7f1d981d29']"

   strings:
      $hex_string = { cb585bfa8f6ba121ee513dd693c488af7baddf0fd8a6ffd77ad15a37ec1d17f58bb5ed0bc05ceaefb70df62da51f7fee44fdce8a947e6781f99d824d4f479c6d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
