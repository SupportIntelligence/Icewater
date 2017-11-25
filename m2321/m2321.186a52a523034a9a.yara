
rule m2321_186a52a523034a9a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.186a52a523034a9a"
     cluster="m2321.186a52a523034a9a"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nimnul vjadtre qvod"
     md5_hashes="['28d9ca7fea36462af769c7c9e8aa2785','431216e92508a040eb902fa45666c011','eeee71c4aff545ed91267bffb4d6ed4f']"

   strings:
      $hex_string = { a436f6e25d017dce864bd7ff85250de3207a729a77db44c2a9cbca916046dca79c06da5ac3c43cc81cd6e41fee40121a70328ea8f4dd7e37cc8d562cf7a37bd1 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
