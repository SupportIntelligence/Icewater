
rule m2321_51347294d6830912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.51347294d6830912"
     cluster="m2321.51347294d6830912"
     cluster_size="62"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="elemental elementa jtvn"
     md5_hashes="['092efc52d0b7cc2c2cc441d3bf1a5493','0a335410e936acdaad086a1ddb95e159','37e2bbae771f29a1d35708acc2de1de8']"

   strings:
      $hex_string = { 8e07c05f823057cae1540b2a32969e37a022b56db81b746483bafb230d3492f91968678d460813cd3bd116298433420d4fce035cd57d7b3c7886e84eb0bf1ed7 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
