
rule m2319_39394cb0dac2e131
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.39394cb0dac2e131"
     cluster="m2319.39394cb0dac2e131"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="inor faceliker redirector"
     md5_hashes="['e598ceb451d23d2228c5d035f4cc7b1ae958e604','6e2cd8a4cc196ef786c79e150e9f52ca0844585d','0e5a0767db7d72310770af8953ed75d1839a2b3f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.39394cb0dac2e131"

   strings:
      $hex_string = { 2b2230313233343536373839414243444546222e63686172417428625b635d253136293b72657475726e20617d3b0a78633d2121776326262266756e6374696f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
