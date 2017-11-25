
rule m3f7_631c6a48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.631c6a48c0000b12"
     cluster="m3f7.631c6a48c0000b12"
     cluster_size="52"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['0674c87d9d337d62a9120b2df01ffc37','0b128d08c93d080d7b2cc5a628a5f735','57818c7570ae676b3c8681536bfa3cbb']"

   strings:
      $hex_string = { 643d315a32593737364b4659464430564e573538505826267265662d72656655524c3d6874747025334125324625324665636f6e6f6d6963736261736963732e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
