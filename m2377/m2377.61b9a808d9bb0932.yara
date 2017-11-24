
rule m2377_61b9a808d9bb0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.61b9a808d9bb0932"
     cluster="m2377.61b9a808d9bb0932"
     cluster_size="5"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['07d24dbc040ff73b5e9f3f4d6c74ced2','2444fc21b0faffda765414b0e41db8ff','e93a31027d37cdf5358a2ea9508fcea4']"

   strings:
      $hex_string = { 6a2e57726974652043687228434c6e6728222648222026204d6964285772697465446174612c692c322929290d0a4e6578740d0a46696c654f626a2e436c6f73 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
