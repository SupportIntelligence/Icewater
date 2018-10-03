
rule n2319_4b993841c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.4b993841c8000b12"
     cluster="n2319.4b993841c8000b12"
     cluster_size="34"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="faceliker likejack clicker"
     md5_hashes="['209ac0109928960a8599f8d63f261b51a3bbe9ec','9139cffd79a2731de95e478f671821c281fcee7e','2fd3a761f82b055be445e813ba239251d16d005e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.4b993841c8000b12"

   strings:
      $hex_string = { 78702e6a73273b0a7661722068656164203d20646f63756d656e742e676574456c656d656e747342795461674e616d6528276865616427295b305d3b0a696620 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
