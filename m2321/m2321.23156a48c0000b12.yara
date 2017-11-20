
rule m2321_23156a48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.23156a48c0000b12"
     cluster="m2321.23156a48c0000b12"
     cluster_size="35"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['07d78ec5a910a8fc66a04da8f48723ac','213290654f26c361cbd6facc45b78b7b','72992d8a3786c141910ce61161866a09']"

   strings:
      $hex_string = { a09cdd0589aa49da4c4fa36c3d957a4a193bfe1df9c65fac864dd55bb5703aa560ca87e3fcd848262882b075224b63503e0f79443cd8618abba2ff2ff3683fcf }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
