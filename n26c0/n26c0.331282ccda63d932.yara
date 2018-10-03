
rule n26c0_331282ccda63d932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26c0.331282ccda63d932"
     cluster="n26c0.331282ccda63d932"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="generickdz malicious kryptik"
     md5_hashes="['2e211f1c62093705a509ae3eae0c8f304efc09a6','c9e1292289e39402a7f265b883b52867a3218f60','ab88b6bd1d3c43ae38490a64c0382a57d1bfb99c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26c0.331282ccda63d932"

   strings:
      $hex_string = { 8d46185750e895c3ffff895e0483c40c33db89be1c02000043395de87651807dee008d45ee74218a480184c9741a0fb6d10fb608eb06804c0e1904413bca76f6 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
