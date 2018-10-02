
rule n231d_0b1c6a48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.0b1c6a48c0000b12"
     cluster="n231d.0b1c6a48c0000b12"
     cluster_size="22891"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos hiddenapp andrsca"
     md5_hashes="['0917827406a445cd313f432bd97982957612a26a','5f542dc0cff35668dc9b6a3c90a9c6c12429c12a','620b810519260c05e830b880b3c08ef6dadbc0c4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.0b1c6a48c0000b12"

   strings:
      $hex_string = { f4535d0dd78435c82b2aaaf6365ad91378bf8db983e8c9404d93e09bc5cecfe26e103b6355667b2bea9ed6455156da3a87a6a48e193038e7c7b108b32750b741 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
