
rule m2321_529b3949c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.529b3949c8000932"
     cluster="m2321.529b3949c8000932"
     cluster_size="47"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['021f84725ff4483b6ed86593b018d70c','02e97aa65c741944b920d8a68bf89535','707ca1a340e9ca7cca2620bd1c1d9777']"

   strings:
      $hex_string = { 016395126d4626913b4c76314ab638f32bdb7bf2d4c73ac61a50e03485f9cbc34b6483c01688f6812e4019732fb88d9ab948f0a0597fdbf8b3b06fd22da65c99 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
