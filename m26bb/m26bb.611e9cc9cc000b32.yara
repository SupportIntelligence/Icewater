
rule m26bb_611e9cc9cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.611e9cc9cc000b32"
     cluster="m26bb.611e9cc9cc000b32"
     cluster_size="40"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="allaple rahack networm"
     md5_hashes="['b8b48d44efde4b6049e9d3d599742513ac75252d','0bbcca4eefcc1a82000f606d96e93f4779122263','66198900029a7ec17e83c929273af3df320f165f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.611e9cc9cc000b32"

   strings:
      $hex_string = { 1b3e126cf35cd8374e9fdd6fb21f1308dfb9874b8f920dcf100e2a6bbc1d31246e46e914bff66809a295aac7c1d4e1ec627ef00fca203655bf4f328d39b01ed5 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
