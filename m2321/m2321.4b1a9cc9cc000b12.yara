
rule m2321_4b1a9cc9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.4b1a9cc9cc000b12"
     cluster="m2321.4b1a9cc9cc000b12"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus sresmon vbkrypt"
     md5_hashes="['03dea8db318e4c4765e059206da67fd5','258882d3d91bd2ce9773b629f726e780','eb3e24e9b93db19cdfe6f95a12caa432']"

   strings:
      $hex_string = { b75c9a254a3ed6342288835f6977847a3da06150ee23a73c224cdc556cbe41d3e0c1911c8ccf32efe379920886e2ae1a00a8190bc9df757dcc21d5f754c2470f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
