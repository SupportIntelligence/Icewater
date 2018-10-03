
rule n26c0_3312108cda63d932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26c0.3312108cda63d932"
     cluster="n26c0.3312108cda63d932"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="generickdz malicious dangerousobject"
     md5_hashes="['987ff3c48960e077d6acfa16ad43336fdf4a8a5f','7f78e60c308b7bd7e829624d3d271d3b5c471294','384d4cde72d043933332e6aa3de2aef6f035a93e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26c0.3312108cda63d932"

   strings:
      $hex_string = { 8d46185750e895c3ffff895e0483c40c33db89be1c02000043395de87651807dee008d45ee74218a480184c9741a0fb6d10fb608eb06804c0e1904413bca76f6 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
