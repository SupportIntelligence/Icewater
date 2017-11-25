
rule k3f7_1a9ee399c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.1a9ee399c2200b12"
     cluster="k3f7.1a9ee399c2200b12"
     cluster_size="5"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cryxos redirector script"
     md5_hashes="['6ccf908cd4e7f7a0f0da69d49e98ae13','7c062f4a409247cb69944c2490a8290f','ffc7768a2e44eeb67a9e4991a05980a1']"

   strings:
      $hex_string = { 5c62272c276727292c6b5b635d297d7d72657475726e20707d28276a2031423d3378284928297b6628712e4f213d315026264d20712e4f213d224c22297b3379 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
