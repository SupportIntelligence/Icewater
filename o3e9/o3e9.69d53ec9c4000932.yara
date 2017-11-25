
rule o3e9_69d53ec9c4000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.69d53ec9c4000932"
     cluster="o3e9.69d53ec9c4000932"
     cluster_size="12"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock nabucur polyransom"
     md5_hashes="['153ad2ea7f2d9cf717899b422ef2a54d','a4de700521d9819e048f851cedd14539','ec28347e1b48b904e4465519fa7295c3']"

   strings:
      $hex_string = { 0042a5f80046b0da002564b700c3b5a6002b78bf001c75ce0055b4c100ae60f500c6c3dd0088b1ee00588cd800266dff0087a4c2002180d5006fa8ea006591ef }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
