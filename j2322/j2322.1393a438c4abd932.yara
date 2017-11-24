
rule j2322_1393a438c4abd932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2322.1393a438c4abd932"
     cluster="j2322.1393a438c4abd932"
     cluster_size="13"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="exploit html iframe"
     md5_hashes="['008ca44d524f6fb2fb3edd5921b1aeff','2297c611f3177467f73dfd996408f41a','f2e9b309c4939042c39e543b7429cc4b']"

   strings:
      $hex_string = { 782e7068703f73656b636a613d7374726f6e612669643d323937223e4e6120706f64727a75636f6e792074656d61742e3c2f613e20283138293c2f6c693e0d0a }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
