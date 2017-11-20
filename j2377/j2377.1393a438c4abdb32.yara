
rule j2377_1393a438c4abdb32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2377.1393a438c4abdb32"
     cluster="j2377.1393a438c4abdb32"
     cluster_size="29"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="exploit html iframe"
     md5_hashes="['0020c6c54b886b087f077800885f1ac3','0876520667935dad05700c06624378aa','9a78eabb3c33f83a877be6e06563b8ae']"

   strings:
      $hex_string = { 782e7068703f73656b636a613d7374726f6e612669643d323937223e4e6120706f64727a75636f6e792074656d61742e3c2f613e20283138293c2f6c693e0d0a }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
