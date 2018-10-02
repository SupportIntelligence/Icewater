
rule m26bb_6390fa59c2200112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.6390fa59c2200112"
     cluster="m26bb.6390fa59c2200112"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="nemesis filerepmetagen malicious"
     md5_hashes="['cca1bb679aef81f3c5881cd070ce5e3d62fd4dd7','b8e907e06abf6c052b1a19618d28629e439ddfd2','1c150e193f61326bbeb912101ae4619ba2a80a10']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.6390fa59c2200112"

   strings:
      $hex_string = { c901894e08ebd98b4c2404a1684742005633f683f920733439356c474200762c8d5008578b02a806751233ff47d3e7857afc74040c01eb0224fe89024681c218 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
