
rule m2377_613c6a4cd8bf0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.613c6a4cd8bf0932"
     cluster="m2377.613c6a4cd8bf0932"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['6107dab9bc1871fc7809b88f985c4234','be75b72fa518ec10c8d30774463a6f94','e9505a18bd0ab260600f0b110530129d']"

   strings:
      $hex_string = { 654f626a6563742822575363726970742e5368656c6c22290d0a5753487368656c6c2e52756e2044726f70506174682c20300d0a2f2f2d2d3e3c2f5343524950 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
