
rule m2377_589b3949c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.589b3949c8000b12"
     cluster="m2377.589b3949c8000b12"
     cluster_size="1001"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['00a72856e04ae9c8edb807c1d31840fd','013142cfacf015f5ba123f2ce1e920b5','060057c8647a8fad1be70c5910142e94']"

   strings:
      $hex_string = { 016395126d4626913b4c76314ab638f32bdb7bf2d4c73ac61a50e03485f9cbc34b6483c01688f6812e4019732fb88d9ab948f0a0597fdbf8b3b06fd22da65c99 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
