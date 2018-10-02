
rule n26c0_3312828cda63d912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26c0.3312828cda63d912"
     cluster="n26c0.3312828cda63d912"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious kryptik prepscram"
     md5_hashes="['8b27748cad65d655dc3cd3b4050ac46830a4272c','ba2211751b034a6a88c8b0f96c8f9f05d23785f5','7bf8447b59f1b5fa0398f77c1d2dc5acc08306f5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26c0.3312828cda63d912"

   strings:
      $hex_string = { 8d46185750e895c3ffff895e0483c40c33db89be1c02000043395de87651807dee008d45ee74218a480184c9741a0fb6d10fb608eb06804c0e1904413bca76f6 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
