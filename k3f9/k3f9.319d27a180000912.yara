
rule k3f9_319d27a180000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f9.319d27a180000912"
     cluster="k3f9.319d27a180000912"
     cluster_size="23"
     filetype = "MS-DOS executable"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="genpack generickdz selfdel"
     md5_hashes="['019d00846cc1b3ad416e4339eaf146c7','3cb74345a4a40cb7c2c78fb7a8af935d','e74b91bc37a5763de6cb066eb3426873']"

   strings:
      $hex_string = { 06092fb4c2114a0486ab5d10ce209a0fda230090f0ebdf2be4d1019164c777d55bc10b416064d70f6189c9be4fd8493142361adc3332212744cb157aea7e951d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
