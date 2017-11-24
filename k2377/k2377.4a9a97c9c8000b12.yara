
rule k2377_4a9a97c9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2377.4a9a97c9c8000b12"
     cluster="k2377.4a9a97c9c8000b12"
     cluster_size="22"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="iframe blackhole fadb"
     md5_hashes="['078ec5430e1e62d8bf52e01e3ae17db5','09460c44463782520213b64bfb462774','e462ab5be1ddcfd9b2bd299b10c44d67']"

   strings:
      $hex_string = { 67653d224a617661536372697074223e0d0a203c212d2d0d0a207334756578743d733475706c28293b0d0a20646f63756d656e742e777269746528273c696d67 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
