
rule n3f7_139dbec1c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f7.139dbec1c8000b32"
     cluster="n3f7.139dbec1c8000b32"
     cluster_size="6"
     filetype = "text/plain"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['0cdbd7b659067e8bed3f6d651fa7bf92','4353ad9e5c1b5db548ae966644fd2ef0','9cf04984a028e72097141806c931f85a']"

   strings:
      $hex_string = { 2f253235285b302d39612d66412d465d7b327d292f672c222524312229292c633d746869732e482c6e756c6c213d632626612e7075736828223a222c53747269 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
