
rule m2321_231a16c9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.231a16c9cc000b12"
     cluster="m2321.231a16c9cc000b12"
     cluster_size="18"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['008343f54286c9b8a525b6e6bc32869a','08ca8b0e97b65630eac046eb0a1ac658','f19ab4a9cf892a2243049e42696ba21a']"

   strings:
      $hex_string = { 8c834412538bd6f23802e2afb24f0429cf263fab7986e08d1e64d5d3072df558c25e549116732068a0e348cd3e66a72abde969890d9d4db60c97f022bb0ed4de }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
