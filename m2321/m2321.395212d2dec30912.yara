
rule m2321_395212d2dec30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.395212d2dec30912"
     cluster="m2321.395212d2dec30912"
     cluster_size="19"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="small generickd upatre"
     md5_hashes="['00143b4d09b5679f08cd59b6e1f4704e','17468a4fb511595e16dccc4d682cbb6e','e5442738f1b887dc89009c7319597e13']"

   strings:
      $hex_string = { a5c8857be7b803ea7d101b0d715231a35d554cac07d8462cefbc06bb04fc8ade2ad2d73ed149b735ed901c10f3e56ba069486de69cb41930bab609aeb1a43a7c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
