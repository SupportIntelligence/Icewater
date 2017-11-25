
rule m3e9_33125492dab34912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.33125492dab34912"
     cluster="m3e9.33125492dab34912"
     cluster_size="23076"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="autorun mepaow lamer"
     md5_hashes="['000300eb136c96416ae14fabd76a258b','00043dd54a678e00b69bad776763c0a9','00257384be0a4db102c284857aa46b16']"

   strings:
      $hex_string = { a2311c3c22fcb7d58623218225434bb92845308178cb1dffb2e9c726af8c33a10d89b67107ed2c0f20aa91e013c101b4e5003f06fac06fde0859807d0c522ae7 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
