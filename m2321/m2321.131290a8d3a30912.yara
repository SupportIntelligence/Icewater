
rule m2321_131290a8d3a30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.131290a8d3a30912"
     cluster="m2321.131290a8d3a30912"
     cluster_size="10"
     filetype = "gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shifu shiz banker"
     md5_hashes="['0284735b7121c0548d3962c8bd6a3fbe','076da80bd8fe0620e2597657d39f0df9','f8bef981f96b261d6b1b67be36ad9de5']"

   strings:
      $hex_string = { 95154702578d5a5b4e84f45ee1815899902f973d6263c75346c693a8ede926c0dcfc7187860f0bd5cc44ab92d0a361a243f6851476aa30045fe200a49aa694df }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
