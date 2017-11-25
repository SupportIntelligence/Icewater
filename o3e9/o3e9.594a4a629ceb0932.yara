
rule o3e9_594a4a629ceb0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.594a4a629ceb0932"
     cluster="o3e9.594a4a629ceb0932"
     cluster_size="9"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply bundler malicious"
     md5_hashes="['151270bfa0f0909ded6fabbb4f1db4d1','4a947074888a185919dca1f177def792','d64972fe93c251c466f4e234b1242a42']"

   strings:
      $hex_string = { 2800250064002900110049006e00760061006c0069006400200063006f0064006500200070006100670065000800460065006200720075006100720079000500 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
