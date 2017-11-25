
rule k2321_2318d64bdfa30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2318d64bdfa30912"
     cluster="k2321.2318d64bdfa30912"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jtlp kryptik hupigon"
     md5_hashes="['60ad185d2bb16cc35da5c89d166abfae','715839ea49a0dedf276e78f4f0f5a7d9','ec700adb43ac4e7d872fbaabcfdcb136']"

   strings:
      $hex_string = { 04bdd43de4924b796206ce0c1afa69e65edf0796a9dcca2cfc8d746e4cb9321ca88a2e3a6763d6adc49bb1a691332fedde0dcd57f92151474ff1141c396ffb8c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
