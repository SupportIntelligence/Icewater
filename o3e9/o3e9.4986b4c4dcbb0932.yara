
rule o3e9_4986b4c4dcbb0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.4986b4c4dcbb0932"
     cluster="o3e9.4986b4c4dcbb0932"
     cluster_size="49"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="strictor dealply riskware"
     md5_hashes="['0a69720e672a91985b6b2e26cfbc297d','0ffede88398afd69053034c595fd4abd','85716089a424c5d9e5a7f905f1df657d']"

   strings:
      $hex_string = { 2800250064002900110049006e00760061006c0069006400200063006f0064006500200070006100670065000800460065006200720075006100720079000500 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
