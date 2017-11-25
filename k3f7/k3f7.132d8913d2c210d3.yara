
rule k3f7_132d8913d2c210d3
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.132d8913d2c210d3"
     cluster="k3f7.132d8913d2c210d3"
     cluster_size="3"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cryxos redir redirector"
     md5_hashes="['33026ec1b9ddceb7dfb798a2d9a22af2','3c2c3b98dbb77b302fe9164cd128710d','ceee3a3f972db4703cd85eb4e3948219']"

   strings:
      $hex_string = { 5c62272c276727292c6b5b635d297d7d72657475726e20707d28276a2031423d3378284928297b6628712e4f213d315026264d20712e4f213d224c22297b3379 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
