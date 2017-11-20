
rule m2318_6939400ad7a30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2318.6939400ad7a30b12"
     cluster="m2318.6939400ad7a30b12"
     cluster_size="39"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['0d6e410d34d91cfccd9c55e55e0a1751','0e44445de2171fac2dbeec6781d308e3','68db1ee29f2f9ce09f0d2fd960fbccf5']"

   strings:
      $hex_string = { 696e672e46696c6553797374656d4f626a65637422290d0a44726f7050617468203d2046534f2e4765745370656369616c466f6c646572283229202620225c22 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
