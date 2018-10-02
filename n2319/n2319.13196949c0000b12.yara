
rule n2319_13196949c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.13196949c0000b12"
     cluster="n2319.13196949c0000b12"
     cluster_size="188"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="hidelink script html"
     md5_hashes="['944191fca5557ef6888c78e14c12a58bb588867e','0d17d06e34b84258043eac33a53fdb9695fd6e28','57a6e0b48007dbaecbc2fc5722be6c1c5b5fe954']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.13196949c0000b12"

   strings:
      $hex_string = { 2b2230313233343536373839414243444546222e63686172417428625b635d253136293b72657475726e20617d3b0a78633d2121776326262266756e6374696f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
