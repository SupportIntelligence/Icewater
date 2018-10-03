
rule m2319_17b109e9c8800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.17b109e9c8800932"
     cluster="m2319.17b109e9c8800932"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery html script"
     md5_hashes="['4d813f9985f1a00d100cebea03146958d4ed0fd7','592b50c99ae00664569be49808f31412a592f9bb','370d8ea6c0328806fd91af2cadf64310ee838f9b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.17b109e9c8800932"

   strings:
      $hex_string = { 3e3c6272202f3e0a0a0a3c21444f43545950452068746d6c205055424c494320222d2f2f5733432f2f445444205848544d4c20312e30205472616e736974696f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
