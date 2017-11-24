
rule m2377_631a96c9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.631a96c9cc000b12"
     cluster="m2377.631a96c9cc000b12"
     cluster_size="6"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['079eadda644af7d8911c5a82ae28d601','14f656cd71bae30fa3f0e7645a895505','c029d0fcceb8601c55a232fb11357634']"

   strings:
      $hex_string = { 5ec22394e28bb98e9eaca9b46d74736bbbe1f40a0224342bccf328ca717bcbaf62c8592904335bed1492729cd71500543ee051ab9097b635c703bccdf0eab038 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
