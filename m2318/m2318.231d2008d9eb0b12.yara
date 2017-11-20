
rule m2318_231d2008d9eb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2318.231d2008d9eb0b12"
     cluster="m2318.231d2008d9eb0b12"
     cluster_size="10"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['1521b7729b92dddb0ff7bd6ad5982936','5173d49cd90be1a28f8b5defc162da5c','ef50a42cf9d22cb1b7d5983eece9a678']"

   strings:
      $hex_string = { 4f626a6563742822575363726970742e5368656c6c22290d0a5753487368656c6c2e52756e2044726f70506174682c20300d0a2f2f2d2d3e3c2f534352495054 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
