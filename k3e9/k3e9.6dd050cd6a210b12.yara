
rule k3e9_6dd050cd6a210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6dd050cd6a210b12"
     cluster="k3e9.6dd050cd6a210b12"
     cluster_size="127"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="netwiredrc riskware aatiu"
     md5_hashes="['06a8fa3ac66b04e3cac9621ba173802c','075fbb0b5ae1de0b10309c7d14703839','2b0f90050237a4a4c4ddd5858de93723']"

   strings:
      $hex_string = { 75a83115f16c9ab68a1bdcec4a5872a9e0b4ed70d3046ee66081b04739017e6f27639ee557a5030e6265c2e98f16af92189cc40538e411c641f04d364e8691b9 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
