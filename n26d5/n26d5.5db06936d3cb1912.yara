
rule n26d5_5db06936d3cb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d5.5db06936d3cb1912"
     cluster="n26d5.5db06936d3cb1912"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious genx"
     md5_hashes="['db303a1971164657ede35404572b075405076680','a63fc468770f8c075b981083beb3d362688b9ea7','e819465b18cf1ece192018e5248fcd81995731aa']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d5.5db06936d3cb1912"

   strings:
      $hex_string = { 977cc135d70adba190136018f7721f5329a59452c669d91a719e7aeaa9e7149f7094abae8d91a2f012a098b9cc63163399423f436d76f2194738cc416ab8ecda }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
