
rule m2321_0b9ab71adee30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0b9ab71adee30912"
     cluster="m2321.0b9ab71adee30912"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['1fe34d7d654dcc915e3dc286998c06bd','5339d8a867a6fd9a40028644307d0bed','eca6bbd2165a77b28ccdb00c32852d80']"

   strings:
      $hex_string = { 3e23af32e7fda743ab6f0e95b5692563f3723f4d0626bb66ee20798cbd30f4b2d30830c473db57ca2996476404c670907d0d13e422760bfc89f18ed1ffc378fb }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
