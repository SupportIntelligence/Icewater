
rule m24c4_0b929518dee30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m24c4.0b929518dee30932"
     cluster="m24c4.0b929518dee30932"
     cluster_size="4"
     filetype = "MS-DOS executable (gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="enistery pemalform riskware"
     md5_hashes="['2aabb0b154302812021ee01ba578fac8','3551589c2177a6322e059d87444c6454','eb84f76003f740dec57fcc3564f3503e']"

   strings:
      $hex_string = { 77c64d7086a29915abf44d6acef17b28cf36e1b96e4564630b41ef6919c71462af24b44608ee52799c84679e958991884abde2566c858b184c34d3b8c29aecfe }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
