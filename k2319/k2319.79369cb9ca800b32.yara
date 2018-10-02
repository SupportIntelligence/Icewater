
rule k2319_79369cb9ca800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.79369cb9ca800b32"
     cluster="k2319.79369cb9ca800b32"
     cluster_size="28"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['71dd194c94393a1bf730c9743dea94b67cc52a89','49062f89a20085315c22b1f19c80e1a16ebe66f4','6d765adf3051f24f8d20dfb17466e0d0c5decd82']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.79369cb9ca800b32"

   strings:
      $hex_string = { 384533293f2836372c322e32394532293a2830783133422c37322e292929627265616b7d3b7661722076366c37683d7b27553068273a66756e6374696f6e2847 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
