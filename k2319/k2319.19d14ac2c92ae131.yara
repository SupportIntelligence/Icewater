
rule k2319_19d14ac2c92ae131
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.19d14ac2c92ae131"
     cluster="k2319.19d14ac2c92ae131"
     cluster_size="6"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="redirector fakejquery script"
     md5_hashes="['2d8fbb7ccea926f4a116ab3aec251319','3ffd81bd69043143c9de1b263109dbe2','be3c2293bf535381091f3928214538b3']"

   strings:
      $hex_string = { 77772e656c6d656a6f726368697374652e636f6d2f3f703d323033223e546f6e746f2c204e616469652079204e696e67756e6f202836262333373b293c2f613e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
