
rule m2377_58993949c4000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.58993949c4000b16"
     cluster="m2377.58993949c4000b16"
     cluster_size="11"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['0b14cc65c348ad8b97f84094efa3fed7','1c5afef3e04dc89d61bc58543a93cd06','efaebcd3ad45aaad132f820ff67409b8']"

   strings:
      $hex_string = { 016395126d4626913b4c76314ab638f32bdb7bf2d4c73ac61a50e03485f9cbc34b6483c01688f6812e4019732fb88d9ab948f0a0597fdbf8b3b06fd22da65c99 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
