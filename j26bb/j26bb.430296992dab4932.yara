
rule j26bb_430296992dab4932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26bb.430296992dab4932"
     cluster="j26bb.430296992dab4932"
     cluster_size="28"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="webprefix xjltf malicious"
     md5_hashes="['60668a24adc68d1426d5067de2e6d55ba92026b0','8d00652a20502c43917dd0bfde1f8f89cebe54eb','fcb1ab1a147edf72d93015e5c70f5433968aedd0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26bb.430296992dab4932"

   strings:
      $hex_string = { 7da5d9060dbc2098140573b3344b9425902d8c9c8f7fb6b1c2c09756b40704b88d450878a65b3cc408e0fc2123bf87b7394301a11c15b41320a8c1696c810971 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
