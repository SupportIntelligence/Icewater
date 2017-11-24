
rule m2319_3b993ec1c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.3b993ec1c4000b32"
     cluster="m2319.3b993ec1c4000b32"
     cluster_size="5"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="clicker faceliker script"
     md5_hashes="['5cd5c6c208be5c09297b5872cc0bb5fb','cc99b32bfbbaaaeabbde140ac5d57863','f8d960ff5654fe09fad11cd4fce81ac8']"

   strings:
      $hex_string = { 7843734b636c79302f5534655145362d657039492f414141414141414153694d2f574532704a39576b6a4e4d2f7337322d632f312e6a7067272077696474683d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
